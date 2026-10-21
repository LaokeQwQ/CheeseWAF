package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Opt-in real PostgreSQL test. It is skipped unless the caller provides an
// isolated database DSN through CHEESEWAF_POSTGRES_TEST_DSN.
func TestPostgreSQLPasskeyStoreIntegration(t *testing.T) {
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
	management, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := management.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store := management.PasskeyStore()
	if store == nil {
		t.Fatal("postgres store did not provide a passkey store")
	}

	credentialID := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 4)
	credential := &passkey.Credential{
		ID:           hex.EncodeToString(credentialID),
		UserID:       "alice",
		CredentialID: credentialID,
		PublicKey:    []byte{0xa1, 0x01, 0x03, 0x26},
		Transports:   []string{"internal", "hybrid"},
		AAGUID:       bytes.Repeat([]byte{0x07}, 16),
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		Name:         "PostgreSQL passkey",
	}
	if err := store.Create(ctx, credential); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Create(ctx, credential); !errors.Is(err, passkey.ErrCredentialExists) {
		t.Fatalf("duplicate Create() error = %v, want ErrCredentialExists", err)
	}
	records, err := store.ListByUser(ctx, "alice")
	if err != nil || len(records) != 1 {
		t.Fatalf("ListByUser() = %d records, %v", len(records), err)
	}
	if !bytes.Equal(records[0].PublicKey, credential.PublicKey) || records[0].Transports[1] != "hybrid" || !bytes.Equal(records[0].AAGUID, credential.AAGUID) {
		t.Fatalf("round-trip mismatch: %+v", records[0])
	}
	if !records[0].LastUsedAt.IsZero() {
		t.Fatalf("new credential LastUsedAt = %s, want zero", records[0].LastUsedAt)
	}
	usedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.UpdateSignCount(ctx, credential.ID, 11, usedAt); err != nil {
		t.Fatalf("UpdateSignCount() error = %v", err)
	}
	updated, err := store.GetByCredentialID(ctx, credentialID)
	if err != nil || updated.SignCount != 11 || !updated.LastUsedAt.Equal(usedAt) {
		t.Fatalf("updated credential = %+v, %v", updated, err)
	}
	if err := store.UpdateSignCount(ctx, "missing", 1, usedAt); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("UpdateSignCount(missing) error = %v, want ErrNotFound", err)
	}

	hash := []byte("recovery-hash")
	if err := store.ReplaceRecoveryCodes(ctx, "alice", [][]byte{hash}, time.Now().UTC()); err != nil {
		t.Fatalf("ReplaceRecoveryCodes() error = %v", err)
	}
	const workers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := store.ConsumeRecoveryCode(ctx, "alice", hash, time.Now().UTC())
			if err != nil {
				t.Errorf("ConsumeRecoveryCode() error = %v", err)
				return
			}
			if consumed {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("successful consumes = %d, want exactly 1", success)
	}
	if consumed, err := store.ConsumeRecoveryCode(ctx, "alice", hash, time.Now().UTC()); err != nil || consumed {
		t.Fatalf("second consume = %v, %v; want false, nil", consumed, err)
	}

	if err := store.RecordAudit(ctx, passkey.AuditEvent{Type: "passkey.admin_reset", UserID: "alice", Actor: "admin", Reason: "lost device", At: time.Now().UTC()}); err != nil {
		t.Fatalf("RecordAudit() error = %v", err)
	}
	if err := store.DeleteByUser(ctx, "alice"); err != nil {
		t.Fatalf("DeleteByUser() error = %v", err)
	}
	if records, err := store.ListByUser(ctx, "alice"); err != nil || len(records) != 0 {
		t.Fatalf("ListByUser() after delete = %d, %v", len(records), err)
	}
}
