package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresApprovalStoreEpochFencingRaceAndReplay(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("approval_epoch_fence_it_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	admin := stdlib.OpenDB(*cfg)
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+quoted+" CASCADE")
		_ = admin.Close()
	})
	testCfg := *cfg
	testCfg.RuntimeParams = map[string]string{}
	for key, value := range cfg.RuntimeParams {
		testCfg.RuntimeParams[key] = value
	}
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(testCfg)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSetEpoch(ctx, 0, 7); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	g, err := approval.NewGateWithPersistence(7, store)
	if err != nil {
		t.Fatal(err)
	}
	confirmRecord, err := g.Submit(now, approval.Request{ID: "pg-fence-confirm", Risk: approval.RiskMedium, Scope: "site:confirm", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-confirm", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("initial confirm request: %v", err)
	}
	revokeRecord, err := g.Submit(now, approval.Request{ID: "pg-fence-revoke", Risk: approval.RiskMedium, Scope: "site:revoke", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-revoke", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("initial revoke request: %v", err)
	}
	preApprovedRecord, err := g.Submit(now, approval.Request{ID: "pg-fence-batch", Risk: approval.RiskLow, Scope: "site:batch", PolicyEpoch: 7, TTL: time.Minute, PreApproved: true, Actor: "scheduler", SessionID: "session-batch", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatalf("initial pre-approved request: %v", err)
	}
	if events, err := store.Events(ctx, preApprovedRecord.ID); err != nil || len(events) != 2 {
		t.Fatalf("pre-approved Submit did not persist an atomic event batch: events=%d err=%v", len(events), err)
	}

	idempotent := approvalMutationForEpochFence("pg-fence-idem", now)
	if err := store.Apply(ctx, idempotent); err != nil {
		t.Fatalf("initial idempotent mutation: %v", err)
	}
	if err := store.Apply(ctx, idempotent); err != nil {
		t.Fatalf("idempotent replay before drift: %v", err)
	}

	advance := holdEpochAdvance(t, db, 7, 8)
	submitDone := make(chan error, 1)
	go func() {
		_, err := g.Submit(now, approval.Request{ID: "pg-fence-submit", Risk: approval.RiskMedium, Scope: "site:submit", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-submit", ConfirmationLanguage: "zh-CN"})
		submitDone <- err
	}()
	assertWriteBlockedUntilCommit(t, submitDone)
	if err := advance.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-submitDone; !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("stale Submit error=%v, want ErrEpochChanged", err)
	}
	if _, err := store.Load(ctx, "pg-fence-submit"); !errors.Is(err, approval.ErrApprovalNotFound) {
		t.Fatalf("stale Submit left durable record: %v", err)
	}
	if err := store.Apply(ctx, idempotent); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("stale idempotent replay error=%v, want ErrEpochChanged", err)
	}
	if err := store.ApplyBatch(ctx, []approval.ApprovalMutation{idempotent}); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("stale ApplyBatch error=%v, want ErrEpochChanged", err)
	}
	if events, err := store.Events(ctx, idempotent.Record.ID); err != nil || len(events) != 1 {
		t.Fatalf("stale replay changed durable events: events=%d err=%v", len(events), err)
	}

	advance = holdEpochAdvance(t, db, 8, 9)
	confirmDone := make(chan error, 1)
	go func() {
		_, err := g.Confirm(now.Add(approval.WarningDelay), confirmRecord.ID, epochFenceConfirmation(confirmRecord, now.Add(approval.WarningDelay)))
		confirmDone <- err
	}()
	assertWriteBlockedUntilCommit(t, confirmDone)
	if err := advance.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-confirmDone; !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("stale Confirm error=%v, want ErrEpochChanged", err)
	}
	if events, err := store.Events(ctx, confirmRecord.ID); err != nil || len(events) != 1 {
		t.Fatalf("stale Confirm changed durable events: events=%d err=%v", len(events), err)
	}
	if got, ok := g.Get(confirmRecord.ID); !ok || got.Status != approval.StatusPending || got.Confirmation.ConfirmationID != "" {
		t.Fatalf("stale Confirm did not restore memory state: %+v ok=%v", got, ok)
	}

	advance = holdEpochAdvance(t, db, 9, 10)
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- g.Revoke(now, revokeRecord.ID, "operator", "epoch drift")
	}()
	assertWriteBlockedUntilCommit(t, revokeDone)
	if err := advance.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-revokeDone; !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("stale Revoke error=%v, want ErrEpochChanged", err)
	}
	if events, err := store.Events(ctx, revokeRecord.ID); err != nil || len(events) != 1 {
		t.Fatalf("stale Revoke changed durable events: events=%d err=%v", len(events), err)
	}
	if got, ok := g.Get(revokeRecord.ID); !ok || got.Status != approval.StatusPending {
		t.Fatalf("stale Revoke did not restore memory state: %+v ok=%v", got, ok)
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM cheesewaf_approval_epoch WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(ctx, idempotent); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("missing checkpoint write error=%v, want ErrEpochChanged", err)
	}
}

func holdEpochAdvance(t *testing.T, db *sql.DB, current, next uint64) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tx.ExecContext(context.Background(), "UPDATE cheesewaf_approval_epoch SET policy_epoch=$1 WHERE id=1 AND policy_epoch=$2", next, current)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if rows != 1 {
		_ = tx.Rollback()
		t.Fatalf("epoch advance affected %d rows, want 1", rows)
	}
	return tx
}

func assertWriteBlockedUntilCommit(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("write completed before epoch transaction committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func approvalMutationForEpochFence(id string, now time.Time) approval.ApprovalMutation {
	req := approval.Request{ID: id, Risk: approval.RiskMedium, Scope: "site:idem", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-idem", ConfirmationLanguage: "zh-CN", WorkflowDigest: "wf-fence"}
	req.Nonce = approval.HashBytes([]byte(id + ":nonce"))[:32]
	req.IntentDigest = approval.IntentDigestForRequest(req)
	record := approval.Record{ID: id, Request: req, Status: approval.StatusPending, SubmittedAt: now, ExpiresAt: now.Add(req.TTL)}
	return approval.ApprovalMutation{IdempotencyKey: "pg-fence-idem-key", WorkflowDigest: req.WorkflowDigest, Record: record, Event: approval.AuditEvent{Sequence: 1, Type: approval.AuditSubmitted, At: now, RequestID: id, Actor: req.Actor, Scope: req.Scope, PolicyEpoch: req.PolicyEpoch}}
}

func epochFenceConfirmation(record approval.Record, now time.Time) approval.Confirmation {
	phrase, _ := approval.ExpectedConfirmationPhrase(record.Request.ConfirmationLanguage)
	return approval.Confirmation{WarningReadAt: now.Add(-approval.WarningDelay), PasswordConfirmed: true, SecondConfirmation: true, ConfirmationID: "pg-fence-confirmation", Actor: record.Request.Actor, Scope: record.Request.Scope, PolicyEpoch: record.Request.PolicyEpoch, TTL: record.Request.TTL, Local: true, SessionID: record.Request.SessionID, ConfirmationLanguage: record.Request.ConfirmationLanguage, ConfirmationPhrase: phrase, IntentDigest: record.Request.IntentDigest, WorkflowDigest: record.Request.WorkflowDigest, Nonce: record.Request.Nonce}
}
