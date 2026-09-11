package migration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	storagepostgres "github.com/LaokeQwQ/CheeseWAF/internal/storage/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// These tests are opt-in because the repository's normal test suite remains
// dependency-free. Each test owns a fresh PostgreSQL schema and never drops
// or truncates data outside that schema.
func migrationPostgresTestDB(t *testing.T, v1Ledger bool) (*sql.DB, context.Context) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN to run migration PostgreSQL integration tests")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL test DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = admin.Close() })
	schema := "cw_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = admin.ExecContext(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE")
	})
	params := map[string]string{}
	for key, value := range cfg.RuntimeParams {
		params[key] = value
	}
	params["search_path"] = schema
	cfg.RuntimeParams = params
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if v1Ledger {
		if _, err := db.ExecContext(ctx, `CREATE TABLE cheesewaf_migration_cutovers (snapshot_id TEXT PRIMARY KEY, config_digest TEXT NOT NULL, candidate_digest TEXT NOT NULL, initial_state_hash TEXT NOT NULL, actor_id TEXT NOT NULL, confirmation_id TEXT NOT NULL UNIQUE, cluster_id TEXT NOT NULL, committed_at TIMESTAMPTZ NOT NULL)`); err != nil {
			t.Fatal(err)
		}
	}
	store, err := storagepostgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db, ctx
}

func TestPostgresV1LedgerUpgradeRemainsExplicitlyUnverified(t *testing.T) {
	db, ctx := migrationPostgresTestDB(t, true)
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-pg-v1", "admin-pg-v1", "confirm-pg-v1", "cluster-pg-v1")
	entry := ledgerEntryForRecoveryRecord(record, time.Now().UTC())
	entry.TokenDigest = legacyTokenMetadataDigestSentinel
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, entry); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var digest string
	if err := db.QueryRowContext(ctx, `SELECT token_metadata_digest FROM cheesewaf_migration_cutovers WHERE snapshot_id=$1`, record.Snapshot.ID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if digest != legacyTokenMetadataDigestSentinel {
		t.Fatalf("upgraded v1 digest=%q, want sentinel", digest)
	}
	if _, err := classifyCutoverState(ctx, db, record); !errors.Is(err, ErrCutoverAmbiguous) || !errors.Is(err, ErrCutoverTokenMetadataUnverified) {
		t.Fatalf("v1 ledger was not rejected with explicit unverified state: %v", err)
	}
}

func TestPostgresV2LedgerAndManagementSnapshotClassifyComplete(t *testing.T) {
	db, ctx := migrationPostgresTestDB(t, false)
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-pg-v2", "admin-pg-v2", "confirm-pg-v2", "cluster-pg-v2")
	record.Snapshot.TokenMetadata = []byte("[]")
	record.Snapshot.ManagementState = postgresManagementSnapshotWithUser(t)
	created := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	if _, err := db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, "user-pg-v2", "admin", "$2a$04$fixture", "admin", false, "", created, created, int64(1)); err != nil {
		t.Fatal(err)
	}
	entry := ledgerEntryForRecoveryRecord(record, created)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, entry); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	direction, err := classifyCutoverState(ctx, db, record)
	if err != nil || direction != RecoveryCompleteProduction {
		t.Fatalf("v2 exact classification direction=%q err=%v", direction, err)
	}
}

func TestPostgresMigrationTransactionRollbackLeavesNoManagementEvidence(t *testing.T) {
	db, ctx := migrationPostgresTestDB(t, false)
	record, _ := newRecoveryRecordFixture(t, t.TempDir(), time.Now().UTC(), "snapshot-pg-rollback", "admin-pg-rollback", "confirm-pg-rollback", "cluster-pg-rollback")
	record.Snapshot.TokenMetadata = []byte(`[{
  "id":"token-pg-rollback",
  "name":"legacy token",
  "prefix":"cw_rollback",
  "hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "scopes":["read"],
  "enabled":true
}]`)
	entry := ledgerEntryForRecoveryRecord(record, time.Now().UTC())
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, "user-pg-rollback", "admin", "$2a$04$fixture", "admin", false, "", time.Now().UTC(), time.Now().UTC(), int64(1)); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := insertCutoverLedger(ctx, tx, entry); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := insertLegacyTokenMetadata(ctx, tx, record.Snapshot.ID, record.Actor, record.Snapshot.TokenMetadata, time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_migration_legacy_tokens(snapshot_id,token_id,name,prefix,scopes,notes,was_enabled,never_expire,migrated_at,actor_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, record.Snapshot.ID, "token-pg-rollback", "duplicate", "cw_duplicate", []byte(`[]`), "", false, false, time.Now().UTC(), record.Actor, migratedLegacyTokenStatus); err == nil {
		_ = tx.Rollback()
		t.Fatal("duplicate legacy token insert unexpectedly succeeded")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id=$1`, "user-pg-rollback").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back management user count=%d", count)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cheesewaf_migration_cutovers WHERE snapshot_id=$1`, record.Snapshot.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back ledger count=%d", count)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cheesewaf_migration_legacy_tokens WHERE snapshot_id=$1`, record.Snapshot.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back legacy token count=%d", count)
	}
}

func postgresManagementSnapshotWithUser(t *testing.T) []byte {
	t.Helper()
	var state managementSnapshot
	if err := json.Unmarshal(emptyRecoveryManagementSnapshot(t), &state); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	for index := range state.Tables {
		if state.Tables[index].Name != "users" {
			continue
		}
		state.Tables[index].Rows = [][]snapshotCell{{
			{Kind: "text", Text: "user-pg-v2"},
			{Kind: "text", Text: "admin"},
			{Kind: "text", Text: "$2a$04$fixture"},
			{Kind: "text", Text: "admin"},
			{Kind: "integer"},
			{Kind: "text"},
			{Kind: "text", Text: created},
			{Kind: "text", Text: created},
			{Kind: "integer"},
		}}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
