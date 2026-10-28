package audit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type postgresJournalFixture struct {
	admin  *sql.DB
	config *pgx.ConnConfig
	schema string
	pools  []*sql.DB
}

func newPostgresJournalFixture(t *testing.T) (*postgresJournalFixture, *sql.DB, *PostgresJournal) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	schema := fmt.Sprintf("audit_journal_it_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer setupCancel()
	if _, err := admin.ExecContext(setupCtx, "CREATE SCHEMA "+quotedSchema); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	fixture := &postgresJournalFixture{admin: admin, config: cfg, schema: schema}
	t.Cleanup(func() {
		for _, pool := range fixture.pools {
			_ = pool.Close()
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := fixture.admin.ExecContext(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated audit schema: %v", err)
		}
		if err := fixture.admin.Close(); err != nil {
			t.Errorf("close audit test admin pool: %v", err)
		}
	})
	db := fixture.openDB(t)
	journal, err := NewPostgresJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := journal.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := journal.Migrate(ctx); err != nil {
		t.Fatalf("Migrate is not idempotent: %v", err)
	}
	return fixture, db, journal
}

func (f *postgresJournalFixture) openDB(t *testing.T) *sql.DB {
	t.Helper()
	cfg := *f.config
	cfg.RuntimeParams = make(map[string]string, len(f.config.RuntimeParams)+1)
	for key, value := range f.config.RuntimeParams {
		cfg.RuntimeParams[key] = value
	}
	cfg.RuntimeParams["search_path"] = f.schema
	db := stdlib.OpenDB(cfg)
	db.SetMaxOpenConns(8)
	f.pools = append(f.pools, db)
	return db
}

func postgresAuditSigner() Ed25519Signer {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	return Ed25519Signer{ID: "audit-test-key", PrivateKey: ed25519.NewKeyFromSeed(seed)}
}

func postgresAuditCommit(t *testing.T, signer Ed25519Signer, stream string, sequence uint64, previous, eventID, reason string, withOutbox bool) Commit {
	t.Helper()
	event := Event{
		EventID: eventID, StreamID: stream, TenantID: "tenant:test", Actor: "admin:test",
		Type: EventTypeAudit, Action: "config.update", Resource: "policy:test",
		Outcome: OutcomeSuccess, Reason: reason, PolicyEpoch: 1,
		Class: EventClassCritical, At: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC).Add(time.Duration(sequence) * time.Second),
	}
	record := Record{Sequence: sequence, Event: event, PreviousHash: previous}
	record.Hash = hashRecord(record)
	commit := Commit{Record: record}
	if signer.PrivateKey != nil {
		checkpoint := Checkpoint{StreamID: stream, Sequence: sequence, Hash: record.Hash, KeyID: signer.KeyID(), At: event.At}
		signature, err := signer.Sign(checkpointMessage(checkpoint))
		if err != nil {
			t.Fatal(err)
		}
		checkpoint.Signature = signature
		commit.Checkpoint = &checkpoint
	}
	if withOutbox {
		commit.Outbox = []Delivery{{
			DeliveryID: deliveryID(stream, sequence, OutboxTargetWORM), Target: OutboxTargetWORM,
			StreamID: stream, Sequence: sequence, EventID: eventID, RecordHash: record.Hash, CreatedAt: event.At,
		}}
	}
	return commit
}

func TestPostgresJournalRoundTripOutboxAndImmutability(t *testing.T) {
	fixture, db, journal := newPostgresJournalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	signer := postgresAuditSigner()
	stream := "audit-stream-test"
	first := postgresAuditCommit(t, signer, stream, 1, "", "event-one", "first", true)
	second := postgresAuditCommit(t, signer, stream, 2, first.Record.Hash, "event-two", "second", true)
	if err := journal.Append(ctx, first); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if err := journal.Append(ctx, second); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	if err := journal.Append(ctx, first); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	conflictingReplay := postgresAuditCommit(t, Ed25519Signer{}, stream, 1, "", "event-one", "different", false)
	if err := journal.Append(ctx, conflictingReplay); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("conflicting replay error=%v, want ErrReplayConflict", err)
	}
	gap := postgresAuditCommit(t, Ed25519Signer{}, stream, 4, second.Record.Hash, "event-four", "gap", false)
	if err := journal.Append(ctx, gap); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("sequence gap error=%v, want ErrSequenceConflict", err)
	}
	duplicateEvent := postgresAuditCommit(t, Ed25519Signer{}, stream, 3, second.Record.Hash, "event-two", "duplicate", false)
	if err := journal.Append(ctx, duplicateEvent); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("duplicate event error=%v, want ErrReplayConflict", err)
	}

	records, err := journal.Records(ctx, stream, 1, 1)
	if err != nil || len(records) != 1 || records[0].Sequence != 2 {
		t.Fatalf("Records page=%+v err=%v", records, err)
	}
	last, err := journal.Last(ctx, stream)
	if err != nil || last.Sequence != 2 || last.Hash != second.Record.Hash {
		t.Fatalf("Last=%+v err=%v", last, err)
	}
	checkpoint, err := journal.Checkpoint(ctx, stream, 1)
	if err != nil || checkpoint == nil {
		t.Fatalf("Checkpoint=%+v err=%v", checkpoint, err)
	}
	publicKeys := map[string]ed25519.PublicKey{signer.KeyID(): signer.PrivateKey.Public().(ed25519.PublicKey)}
	if err := VerifyCheckpoint(stream, first.Record, *checkpoint, publicKeys); err != nil {
		t.Fatalf("persisted checkpoint signature did not verify: %v", err)
	}

	pending, err := journal.PendingOutbox(ctx, stream, 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("PendingOutbox=%+v err=%v", pending, err)
	}
	wrongAck := pending[0]
	wrongAck.EventID = "event-other"
	if err := journal.AckOutbox(ctx, wrongAck); !errors.Is(err, ErrOutboxConflict) {
		t.Fatalf("wrong acknowledgement error=%v, want ErrOutboxConflict", err)
	}
	ack := pending[0]
	ack.DeliveredAt = time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	if err := journal.AckOutbox(ctx, ack); err != nil {
		t.Fatalf("AckOutbox: %v", err)
	}
	if err := journal.AckOutbox(ctx, pending[0]); err != nil {
		t.Fatalf("idempotent AckOutbox: %v", err)
	}
	pending, err = journal.PendingOutbox(ctx, stream, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("PendingOutbox after ack=%+v err=%v", pending, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE cheesewaf_audit_records SET record_hash=$3 WHERE stream_id=$1 AND sequence=$2`, stream, int64(1), strings.Repeat("f", 64)); err == nil {
		t.Fatal("record update bypassed append-only trigger")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM cheesewaf_audit_records WHERE stream_id=$1 AND sequence=$2`, stream, int64(1)); err == nil {
		t.Fatal("record delete bypassed append-only trigger")
	}
	if _, err := db.ExecContext(ctx, `UPDATE cheesewaf_audit_outbox SET target='siem' WHERE delivery_id=$1`, pending[0].DeliveryID); err == nil {
		t.Fatal("outbox identity update bypassed immutability trigger")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM cheesewaf_audit_outbox WHERE delivery_id=$1`, pending[0].DeliveryID); err == nil {
		t.Fatal("outbox delete bypassed append-only trigger")
	}
	if err := journal.Verify(ctx, stream); err != nil {
		t.Fatalf("Verify before reopen: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedDB := fixture.openDB(t)
	reopened, err := NewPostgresJournal(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Verify(ctx, stream); err != nil {
		t.Fatalf("Verify after reopen: %v", err)
	}
	runtime, err := NewRuntime(RuntimeOptions{
		Journal: reopened, StreamID: stream,
		Verifiers: publicKeys,
	})
	if err != nil {
		t.Fatalf("NewRuntime did not verify persisted checkpoints: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close reopened runtime: %v", err)
	}
	if _, err := reopenedDB.ExecContext(ctx, `UPDATE cheesewaf_audit_streams SET head_sequence=3 WHERE stream_id=$1`, stream); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Verify(ctx, stream); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("mismatched stream head error=%v, want ErrCorruptChain", err)
	}
}

func TestPostgresJournalAppendAtomicityAndIndependentWriters(t *testing.T) {
	fixture, _, journal := newPostgresJournalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	signer := postgresAuditSigner()
	stream := "audit-stream-atomic"
	first := postgresAuditCommit(t, Ed25519Signer{}, stream, 1, "", "atomic-one", "first", true)
	if err := journal.Append(ctx, first); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	conflictingOutbox := postgresAuditCommit(t, Ed25519Signer{}, stream, 2, first.Record.Hash, "atomic-two", "second", true)
	conflictingOutbox.Outbox[0].DeliveryID = first.Outbox[0].DeliveryID
	if err := journal.Append(ctx, conflictingOutbox); !errors.Is(err, ErrOutboxConflict) {
		t.Fatalf("outbox collision error=%v, want ErrOutboxConflict", err)
	}
	last, err := journal.Last(ctx, stream)
	if err != nil || last.Sequence != 1 {
		t.Fatalf("failed append advanced chain: Last=%+v err=%v", last, err)
	}
	if err := journal.Append(ctx, postgresAuditCommit(t, Ed25519Signer{}, stream, 2, first.Record.Hash, "atomic-two", "second", true)); err != nil {
		t.Fatalf("valid append after rollback: %v", err)
	}

	concurrentStream := "audit-stream-concurrent"
	leftDB := fixture.openDB(t)
	rightDB := fixture.openDB(t)
	left, err := NewPostgresJournal(leftDB)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewPostgresJournal(rightDB)
	if err != nil {
		t.Fatal(err)
	}
	commits := []Commit{
		postgresAuditCommit(t, signer, concurrentStream, 1, "", "writer-left", "left", false),
		postgresAuditCommit(t, signer, concurrentStream, 1, "", "writer-right", "right", false),
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, writer := range []*PostgresJournal{left, right} {
		commit := commits[index]
		go func(journal *PostgresJournal) {
			<-start
			results <- journal.Append(ctx, commit)
		}(writer)
	}
	close(start)
	firstErr, secondErr := <-results, <-results
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("concurrent append results=%v, %v; want exactly one success", firstErr, secondErr)
	}
	winnerError := firstErr
	if winnerError == nil {
		winnerError = secondErr
	}
	if !errors.Is(winnerError, ErrReplayConflict) && !errors.Is(winnerError, ErrSequenceConflict) {
		t.Fatalf("losing writer error=%v, want replay or sequence conflict", winnerError)
	}
	if err := left.Verify(ctx, concurrentStream); err != nil {
		t.Fatalf("Verify concurrent stream: %v", err)
	}
	last, err = right.Last(ctx, concurrentStream)
	if err != nil || last.Sequence != 1 {
		t.Fatalf("concurrent Last=%+v err=%v", last, err)
	}
	if _, err := leftDB.ExecContext(ctx, `CREATE FUNCTION audit_test_delay_append() RETURNS trigger AS $$ BEGIN PERFORM pg_sleep(0.005); RETURN NEW; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create isolated append delay trigger function: %v", err)
	}
	if _, err := leftDB.ExecContext(ctx, `CREATE TRIGGER audit_test_delay_append BEFORE INSERT ON cheesewaf_audit_records FOR EACH ROW EXECUTE FUNCTION audit_test_delay_append()`); err != nil {
		t.Fatalf("create isolated append delay trigger: %v", err)
	}

	stopVerify := make(chan struct{})
	verifyDone := make(chan struct{})
	verifyReady := make(chan struct{}, 1)
	verifyErrors := make(chan error, 1)
	var verifyRuns atomic.Uint64
	var overlappingVerifies atomic.Uint64
	var appendActive atomic.Bool
	go func() {
		defer close(verifyDone)
		for {
			select {
			case <-stopVerify:
				return
			default:
			}
			if err := right.Verify(ctx, concurrentStream); err != nil {
				select {
				case verifyErrors <- err:
				default:
				}
				return
			}
			verifyRuns.Add(1)
			if appendActive.Load() {
				overlappingVerifies.Add(1)
			}
			select {
			case verifyReady <- struct{}{}:
			default:
			}
			time.Sleep(time.Millisecond)
		}
	}()
	<-verifyReady
	previous := last.Hash
	for sequence := uint64(2); sequence <= 41; sequence++ {
		commit := postgresAuditCommit(t, Ed25519Signer{}, concurrentStream, sequence, previous, fmt.Sprintf("writer-%d", sequence), "stress", false)
		appendActive.Store(true)
		if err := left.Append(ctx, commit); err != nil {
			appendActive.Store(false)
			close(stopVerify)
			<-verifyDone
			t.Fatalf("append while verifying sequence %d: %v", sequence, err)
		}
		appendActive.Store(false)
		previous = commit.Record.Hash
	}
	close(stopVerify)
	<-verifyDone
	select {
	case err := <-verifyErrors:
		t.Fatalf("concurrent Verify: %v", err)
	default:
	}
	if verifyRuns.Load() == 0 || overlappingVerifies.Load() == 0 {
		t.Fatalf("Verify did not overlap appends: runs=%d overlaps=%d", verifyRuns.Load(), overlappingVerifies.Load())
	}
	last, err = right.Last(ctx, concurrentStream)
	if err != nil || last.Sequence != 41 {
		t.Fatalf("last after concurrent append=%+v err=%v", last, err)
	}
}
