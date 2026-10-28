package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
)

func newPasskeyTestStore(t *testing.T) *PasskeyStore {
	t.Helper()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "passkey.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	passkeyStore, ok := store.PasskeyStore().(*PasskeyStore)
	if !ok {
		t.Fatal("SQLite store did not provide a concrete passkey store")
	}
	return passkeyStore
}

func testStoragePasskeyCredential(userID string, seed byte) *passkey.Credential {
	credentialID := bytes.Repeat([]byte{seed, 0x01, 0x02, 0x03}, 4)
	return &passkey.Credential{
		ID:           hex.EncodeToString(credentialID),
		UserID:       userID,
		CredentialID: credentialID,
		PublicKey:    []byte{0xa1, 0x01, 0x03, 0x26},
		SignCount:    1,
		Transports:   []string{"internal", "hybrid"},
		AAGUID:       bytes.Repeat([]byte{seed}, 16),
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		Name:         "Storage Test Passkey",
	}
}

func TestSQLitePasskeyStoreContract(t *testing.T) {
	store := newPasskeyTestStore(t)
	ctx := context.Background()

	first := testStoragePasskeyCredential("alice", 1)
	second := testStoragePasskeyCredential("alice", 2)
	other := testStoragePasskeyCredential("bob", 3)
	for _, credential := range []*passkey.Credential{first, second, other} {
		if err := store.Create(ctx, credential); err != nil {
			t.Fatalf("Create(%s) error = %v", credential.ID, err)
		}
	}

	records, err := store.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ListByUser() returned %d records, want 2", len(records))
	}
	var firstRecord *passkey.Credential
	for i := range records {
		if records[i].ID == first.ID {
			firstRecord = records[i]
			break
		}
	}
	if firstRecord == nil {
		t.Fatalf("ListByUser() dropped the first credential: %+v", records)
	}
	if firstRecord.Transports[0] != "internal" || !bytes.Equal(firstRecord.AAGUID, first.AAGUID) {
		t.Fatalf("round-trip lost transports or AAGUID: %+v", firstRecord)
	}
	if !firstRecord.LastUsedAt.IsZero() {
		t.Fatalf("new credential LastUsedAt = %s, want zero", firstRecord.LastUsedAt)
	}

	got, err := store.GetByCredentialID(ctx, first.CredentialID)
	if err != nil || got.ID != first.ID {
		t.Fatalf("GetByCredentialID() = %+v, %v", got, err)
	}

	if err := store.Create(ctx, first); !errors.Is(err, passkey.ErrCredentialExists) {
		t.Fatalf("duplicate record error = %v, want ErrCredentialExists", err)
	}
	duplicateID := testStoragePasskeyCredential("alice", 4)
	duplicateID.CredentialID = append([]byte(nil), first.CredentialID...)
	if err := store.Create(ctx, duplicateID); !errors.Is(err, passkey.ErrCredentialExists) {
		t.Fatalf("duplicate credential ID error = %v, want ErrCredentialExists", err)
	}
	if err := store.Create(ctx, nil); !errors.Is(err, passkey.ErrInvalidCredential) {
		t.Fatalf("nil credential error = %v, want ErrInvalidCredential", err)
	}

	usedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.UpdateSignCount(ctx, first.ID, 9, usedAt); err != nil {
		t.Fatalf("UpdateSignCount() error = %v", err)
	}
	got, err = store.GetByCredentialID(ctx, first.CredentialID)
	if err != nil {
		t.Fatalf("GetByCredentialID() after update error = %v", err)
	}
	if got.SignCount != 9 || !got.LastUsedAt.Equal(usedAt) {
		t.Fatalf("updated credential = sign %d, last used %s", got.SignCount, got.LastUsedAt)
	}
	if err := store.UpdateSignCount(ctx, "missing", 1, usedAt); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("UpdateSignCount(missing) error = %v, want ErrNotFound", err)
	}

	if err := store.Delete(ctx, second.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := store.Delete(ctx, second.ID); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}
	if _, err := store.GetByCredentialID(ctx, second.CredentialID); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("GetByCredentialID(deleted) error = %v, want ErrNotFound", err)
	}

	if err := store.ReplaceRecoveryCodes(ctx, "alice", [][]byte{[]byte("hash-one"), []byte("hash-two")}, time.Now().UTC()); err != nil {
		t.Fatalf("ReplaceRecoveryCodes() error = %v", err)
	}
	if err := store.DeleteByUser(ctx, "alice"); err != nil {
		t.Fatalf("DeleteByUser() error = %v", err)
	}
	if records, err := store.ListByUser(ctx, "alice"); err != nil || len(records) != 0 {
		t.Fatalf("ListByUser() after delete = %d, %v", len(records), err)
	}
	if consumed, err := store.ConsumeRecoveryCode(ctx, "alice", []byte("hash-one"), time.Now().UTC()); err != nil || consumed {
		t.Fatalf("recovery code survived DeleteByUser(): consumed=%v err=%v", consumed, err)
	}
	if _, err := store.GetByCredentialID(ctx, other.CredentialID); err != nil {
		t.Fatalf("other user's credential was deleted: %v", err)
	}
}

func TestSQLitePasskeyRecoveryCodeConsumeIsAtomic(t *testing.T) {
	store := newPasskeyTestStore(t)
	ctx := context.Background()
	hash := []byte("single-use-hash")

	if err := store.ReplaceRecoveryCodes(ctx, "alice", [][]byte{hash}, time.Now().UTC()); err != nil {
		t.Fatalf("ReplaceRecoveryCodes() error = %v", err)
	}

	const workers = 16
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
	if consumed, err := store.ConsumeRecoveryCode(ctx, "bob", hash, time.Now().UTC()); err != nil || consumed {
		t.Fatalf("other user consume = %v, %v; want false, nil", consumed, err)
	}
}

func TestSQLitePasskeyAuditAndBounds(t *testing.T) {
	store := newPasskeyTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	event := passkey.AuditEvent{Type: "passkey.admin_reset", UserID: "alice", Actor: "admin", Reason: "lost device", At: at}
	if err := store.RecordAudit(ctx, event); err != nil {
		t.Fatalf("RecordAudit() error = %v", err)
	}
	var (
		eventType, actor, reason, createdAt string
	)
	if err := store.db.QueryRow(`SELECT type, actor, reason, created_at FROM passkey_audit_events WHERE user_id='alice'`).Scan(&eventType, &actor, &reason, &createdAt); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if eventType != event.Type || actor != event.Actor || reason != event.Reason || !parseTime(createdAt).Equal(at) {
		t.Fatalf("audit row = %q %q %q %s", eventType, actor, reason, createdAt)
	}
	if err := store.RecordAudit(ctx, passkey.AuditEvent{Type: "", UserID: "alice"}); err == nil {
		t.Fatal("audit without a type must fail")
	}
	if err := store.ReplaceRecoveryCodes(ctx, "alice", make([][]byte, passkey.MaxRecoveryCodes+1), time.Now().UTC()); !errors.Is(err, passkey.ErrInvalidRecoveryCode) {
		t.Fatalf("oversized recovery codes error = %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ListByUser(cancelled, "alice"); err == nil {
		t.Fatal("cancelled context must fail the query")
	}
}
