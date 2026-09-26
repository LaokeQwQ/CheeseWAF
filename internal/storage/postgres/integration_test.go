package postgres

import (
	"context"
	"database/sql"
	"errors"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"testing"
	"time"
)

// Opt-in real PostgreSQL test. It is skipped unless the caller provides an
// isolated database DSN through CHEESEWAF_POSTGRES_TEST_DSN.
func TestPostgreSQLManagementStoreIntegration(t *testing.T) {
	dsn := os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN to run real PostgreSQL integration tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := db.QueryRowContext(ctx, `SELECT 'cw_test_' || substr(md5(random()::text),1,12)`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx); err != nil {
		t.Fatal(err)
	}
	committedAt := time.Date(2026, 9, 22, 12, 0, 0, 123456789, time.UTC)
	handoff := storage.MigrationHandoffEvidence{
		SnapshotID:             "snapshot-pg-precision",
		TemporaryConfigDigest:  "temporary-config-digest",
		ProductionConfigDigest: "production-config-digest",
		CandidateDigest:        "candidate-digest",
		InitialStateHash:       "initial-state-hash",
		TokenMetadataDigest:    "token-metadata-digest",
		ClusterID:              "cluster-a",
		Actor:                  "admin-a",
		CommittedAt:            committedAt,
		SessionsInvalidated:    true,
		SetupInvalidated:       true,
		JoinInvalidated:        true,
		CAPTCHAInvalidated:     true,
		LocksInvalidated:       true,
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO cheesewaf_migration_cutovers(snapshot_id,config_digest,candidate_digest,initial_state_hash,token_metadata_digest,actor_id,confirmation_id,cluster_id,committed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		handoff.SnapshotID, handoff.TemporaryConfigDigest, handoff.CandidateDigest, handoff.InitialStateHash,
		handoff.TokenMetadataDigest, handoff.Actor, "confirmation-a", handoff.ClusterID, handoff.CommittedAt); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyMigrationHandoff(ctx, handoff); err != nil {
		t.Fatalf("migration handoff rejected PostgreSQL timestamp precision: %v", err)
	}
	user := &storage.User{Username: "admin", PasswordHash: "hash-a", Role: "admin"}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	session := &storage.Session{ID: "session-a", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	active, err := s.IsSessionActive(ctx, session.ID, user.ID, time.Now())
	if err != nil || !active {
		t.Fatalf("session active=%v err=%v", active, err)
	}
	stale := *user
	stale.PasswordHash = "stale"
	user.PasswordHash = "hash-b"
	if err := s.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.UpdateUser(ctx, &stale), storage.ErrCredentialEpochChanged) {
		t.Fatal("stale credential update was accepted")
	}
	active, err = s.IsSessionActive(ctx, session.ID, user.ID, time.Now())
	if err != nil || active {
		t.Fatalf("revoked session active=%v err=%v", active, err)
	}
}

func TestPostgreSQLTOTPConsumeAtomicIntegration(t *testing.T) {
	dsn := os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN to run real PostgreSQL TOTP atomic-consume integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	firstDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer firstDB.Close()
	secondDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer secondDB.Close()
	firstDB.SetMaxOpenConns(1)
	secondDB.SetMaxOpenConns(1)
	if err := firstDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := secondDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	var schema string
	if err := firstDB.QueryRowContext(ctx, `SELECT 'cw_totp_' || substr(md5(random()::text),1,12)`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := firstDB.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer firstDB.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	if _, err := firstDB.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := secondDB.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}

	first, err := New(firstDB)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(secondDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	expires := now.Add(120 * time.Second)
	start := make(chan struct{})
	results := make(chan bool, 2)
	for _, store := range []*Store{first, second} {
		go func(store *Store) {
			<-start
			claimed, err := store.ConsumeTOTP(ctx, "user-1", 123, expires, now)
			if err != nil {
				t.Errorf("concurrent PostgreSQL atomic consume: %v", err)
				return
			}
			results <- claimed
		}(store)
	}
	close(start)
	claimedCount := 0
	for range []*Store{first, second} {
		if <-results {
			claimedCount++
		}
	}
	if claimedCount != 1 {
		t.Fatalf("concurrent PostgreSQL atomic consume successes=%d, want exactly 1", claimedCount)
	}

	claimed, err := first.ConsumeTOTP(ctx, "user-1", 123, expires.Add(120*time.Second), expires.Add(time.Second))
	if err != nil {
		t.Fatalf("expired PostgreSQL atomic consume: %v", err)
	}
	if !claimed {
		t.Fatal("expired PostgreSQL counter must be consumable again")
	}
}
