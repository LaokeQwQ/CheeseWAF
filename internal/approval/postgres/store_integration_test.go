package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
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

func TestPostgresApprovalStoreRoundTripAndTamperFailClosed(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("approval_it_%d", time.Now().UnixNano())
	admin := stdlib.OpenDB(*cfg)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA "+quoted+" CASCADE"); _ = admin.Close() })
	testCfg := *cfg
	testCfg.RuntimeParams = map[string]string{}
	for k, v := range cfg.RuntimeParams {
		testCfg.RuntimeParams[k] = v
	}
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(testCfg)
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
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	req := approval.Request{ID: "pg-roundtrip", Risk: approval.RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN", WorkflowDigest: "wf-pg"}
	req.Nonce = nonceForIntegration(req)
	req.IntentDigest = approval.IntentDigestForRequest(req)
	record := approval.Record{ID: req.ID, Request: req, Status: approval.StatusPending, SubmittedAt: now, ExpiresAt: now.Add(req.TTL)}
	mutation := approval.ApprovalMutation{IdempotencyKey: "pg-idem", WorkflowDigest: req.WorkflowDigest, Record: record, Event: approval.AuditEvent{Sequence: 1, Type: approval.AuditSubmitted, At: now, RequestID: req.ID, Actor: req.Actor, Scope: req.Scope, PolicyEpoch: req.PolicyEpoch}}
	if err := store.Apply(ctx, mutation); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ctx, req.ID)
	if err != nil || loaded.ID != req.ID {
		t.Fatalf("Load=%+v err=%v", loaded, err)
	}
	events, err := store.Events(ctx, req.ID)
	if err != nil || len(events) != 1 {
		t.Fatalf("Events=%+v err=%v", events, err)
	}
	snapshotRecord, snapshotEvents, err := store.LoadWithEvents(ctx, req.ID)
	if err != nil || snapshotRecord.ID != req.ID || len(snapshotEvents) != 1 {
		t.Fatalf("LoadWithEvents record=%+v events=%+v err=%v", snapshotRecord, snapshotEvents, err)
	}
	epochRecord, epochEvents, err := store.LoadWithEventsAtEpoch(ctx, req.ID, 7)
	if err != nil || epochRecord.ID != req.ID || len(epochEvents) != 1 {
		t.Fatalf("LoadWithEventsAtEpoch record=%+v events=%+v err=%v", epochRecord, epochEvents, err)
	}
	if _, _, err := store.LoadWithEventsAtEpoch(ctx, req.ID, 8); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("LoadWithEventsAtEpoch mismatch error=%v, want ErrEpochChanged", err)
	}
	ids, err := store.ListIDs(ctx)
	if err != nil || len(ids) != 1 || ids[0] != req.ID {
		t.Fatalf("ListIDs=%v err=%v", ids, err)
	}
	gate, err := approval.NewGateWithPersistence(7, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.RestoreRecord(ctx, now, req.ID); err != nil {
		t.Fatal(err)
	}

	var original []byte
	if err := db.QueryRowContext(ctx, "SELECT event_json FROM cheesewaf_approval_events WHERE request_id=$1 AND sequence=1", req.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	t.Run("event json tamper", func(t *testing.T) {
		_, err := db.ExecContext(ctx, "UPDATE cheesewaf_approval_events SET event_json=$2 WHERE request_id=$1 AND sequence=1", req.ID, []byte(`{"sequence":1,"type":"submitted","request_id":"pg-roundtrip","scope":"site:tampered"}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Events(ctx, req.ID); err == nil {
			t.Fatal("tampered JSON accepted")
		}
		restoreEventJSON(t, db, req.ID, original, events[0].Hash)
	})
	t.Run("event hash tamper", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, "UPDATE cheesewaf_approval_events SET event_hash=$2 WHERE request_id=$1 AND sequence=1", req.ID, strings.Repeat("f", 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Events(ctx, req.ID); err == nil {
			t.Fatal("tampered event_hash accepted")
		}
		restoreEventJSON(t, db, req.ID, original, events[0].Hash)
	})
	for _, field := range []string{"scope", "policy_epoch", "intent_digest", "session_id", "nonce", "workflow_digest"} {
		t.Run(field, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(original, &raw); err != nil {
				t.Fatal(err)
			}
			value := map[string]any{"scope": "site:tampered", "policy_epoch": 8, "intent_digest": strings.Repeat("a", 64), "session_id": "session-b", "nonce": "nonce-b", "workflow_digest": "wf-other"}[field]
			raw[field] = value
			raw["hash"] = ""
			body, _ := json.Marshal(raw)
			hash := approval.HashBytes(body)
			raw["hash"] = hash
			body, _ = json.Marshal(raw)
			if _, err := db.ExecContext(ctx, "UPDATE cheesewaf_approval_events SET event_json=$2,event_hash=$3 WHERE request_id=$1 AND sequence=1", req.ID, body, hash); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Events(ctx, req.ID); !errors.Is(err, approval.ErrBindingConflict) {
				t.Fatalf("Events() error=%v", err)
			}
			restoreEventJSON(t, db, req.ID, original, events[0].Hash)
		})
	}
}

func restoreEventJSON(t *testing.T, db *sql.DB, id string, body []byte, hash string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), "UPDATE cheesewaf_approval_events SET event_json=$2,event_hash=$3 WHERE request_id=$1 AND sequence=1", id, body, hash); err != nil {
		t.Fatal(err)
	}
}
func nonceForIntegration(r approval.Request) string {
	return approval.HashBytes([]byte(r.ID + ":" + r.Scope + ":" + r.Actor))[:32]
}

func TestPostgresApprovalEpochCASAndGateConsistency(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("approval_epoch_it_%d", time.Now().UnixNano())
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
	for k, v := range cfg.RuntimeParams {
		testCfg.RuntimeParams[k] = v
	}
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(testCfg)
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

	gate, err := approval.NewGateWithPersistence(7, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.AdvanceEpoch(6); !errors.Is(err, approval.ErrEpochRegression) {
		t.Fatalf("rollback error=%v, want epoch regression", err)
	}
	if got, err := store.PolicyEpoch(ctx); err != nil || got != 7 {
		t.Fatalf("rollback changed durable epoch: got=%d err=%v", got, err)
	}
	if err := gate.AdvanceEpoch(8); err != nil {
		t.Fatalf("AdvanceEpoch(8): %v", err)
	}
	if got, err := store.PolicyEpoch(ctx); err != nil || got != 8 {
		t.Fatalf("successful advance did not persist: got=%d err=%v", got, err)
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM cheesewaf_approval_epoch WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSetEpoch(ctx, 8, 9); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("missing non-zero checkpoint error=%v, want epoch changed", err)
	}
	if _, err := store.PolicyEpoch(ctx); !errors.Is(err, approval.ErrApprovalNotFound) {
		t.Fatalf("missing checkpoint was recreated: PolicyEpoch error=%v", err)
	}

	if err := store.CompareAndSetEpoch(ctx, 0, 9); err != nil {
		t.Fatalf("recreate checkpoint: %v", err)
	}
	if err := gate.AdvanceEpoch(10); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("CAS mismatch error=%v, want epoch changed", err)
	}
	if err := gate.AdvanceEpoch(9); !errors.Is(err, approval.ErrEpochChanged) {
		t.Fatalf("stale gate was allowed to adopt an externally advanced epoch: %v", err)
	}
	// Recovery from an externally advanced durable epoch is explicit: a new
	// Gate must be constructed at the observed epoch rather than silently
	// mutating the stale in-memory authority.
	reconciled, err := approval.NewGateWithPersistence(9, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciled.AdvanceEpoch(9); err != nil {
		t.Fatalf("reconciled gate did not accept current epoch: %v", err)
	}
	if got, err := store.PolicyEpoch(ctx); err != nil || got != 9 {
		t.Fatalf("durable epoch changed unexpectedly after stale-gate rejection: got=%d err=%v", got, err)
	}
	if err := reconciled.AdvanceEpoch(8); !errors.Is(err, approval.ErrEpochRegression) {
		t.Fatalf("post-reconciliation rollback error=%v, want epoch regression", err)
	}
}

func TestPostgresApprovalStoreHealthProbesAllTablesWithoutPersistingRows(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("approval_health_it_%d", time.Now().UnixNano())
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
	for k, v := range cfg.RuntimeParams {
		testCfg.RuntimeParams[k] = v
	}
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(testCfg)
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
	if err := store.Health(ctx); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	for _, table := range []string{"cheesewaf_approvals", "cheesewaf_approval_events", "cheesewaf_approval_idempotency"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("Health() persisted %d probe rows in %s", count, table)
		}
	}
	var epoch uint64
	if err := db.QueryRowContext(ctx, "SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1").Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	if epoch != 7 {
		t.Fatalf("Health() changed epoch to %d, want 7", epoch)
	}
	t.Run("write-only permissions fail closed", func(t *testing.T) {
		role := fmt.Sprintf("approval_health_writer_%d", time.Now().UnixNano())
		quotedRole := pgx.Identifier{role}.Sanitize()
		if _, err := admin.ExecContext(ctx, "CREATE ROLE "+quotedRole+" NOLOGIN"); err != nil {
			t.Skipf("write-only permission probe requires CREATEROLE: %v", err)
		}
		t.Cleanup(func() {
			_, _ = admin.ExecContext(ctx, "REVOKE "+quotedRole+" FROM CURRENT_USER")
			_, _ = admin.ExecContext(ctx, "DROP ROLE "+quotedRole)
		})
		if _, err := admin.ExecContext(ctx, "GRANT "+quotedRole+" TO CURRENT_USER"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, "GRANT USAGE ON SCHEMA "+quoted+" TO "+quotedRole); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			"GRANT INSERT, UPDATE ON cheesewaf_approvals TO " + quotedRole,
			"GRANT INSERT ON cheesewaf_approval_events TO " + quotedRole,
			"GRANT INSERT ON cheesewaf_approval_idempotency TO " + quotedRole,
			"GRANT UPDATE ON cheesewaf_approval_epoch TO " + quotedRole,
		} {
			if _, err := admin.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		writeOnlyCfg := testCfg
		writeOnlyCfg.RuntimeParams = map[string]string{}
		for k, v := range testCfg.RuntimeParams {
			writeOnlyCfg.RuntimeParams[k] = v
		}
		writeOnlyCfg.RuntimeParams["role"] = role
		writeOnlyDB := stdlib.OpenDB(writeOnlyCfg)
		t.Cleanup(func() { _ = writeOnlyDB.Close() })
		writeOnlyStore, err := New(writeOnlyDB)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeOnlyStore.Health(ctx); err == nil {
			t.Fatal("Health() accepted write-only approval table permissions")
		}
	})
	if _, err := db.ExecContext(ctx, "DROP TABLE cheesewaf_approval_idempotency"); err != nil {
		t.Fatal(err)
	}
	if err := store.Health(ctx); err == nil {
		t.Fatal("Health() accepted a missing idempotency table")
	}
}
