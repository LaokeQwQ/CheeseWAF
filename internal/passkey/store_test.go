package passkey

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCredentialStoreContract(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()

	first := testCredential("admin", 1)
	second := testCredential("admin", 2)
	other := testCredential("operator", 3)

	if err := store.Create(ctx, first); err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}

	if err := store.Create(ctx, second); err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}

	if err := store.Create(ctx, other); err != nil {
		t.Fatalf("Create(other) error = %v", err)
	}

	records, err := store.ListByUser(ctx, "admin")
	if err != nil {
		t.Fatalf("ListByUser() error = %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("ListByUser() returned %d records, want 2", len(records))
	}

	got, err := store.GetByCredentialID(ctx, first.CredentialID)
	if err != nil {
		t.Fatalf("GetByCredentialID() error = %v", err)
	}

	if got.ID != first.ID {
		t.Fatalf("GetByCredentialID() ID = %q, want %q", got.ID, first.ID)
	}

	if err := store.Create(ctx, first); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate ID error = %v, want ErrCredentialExists", err)
	}

	duplicateCredentialID := testCredential("admin", 4)
	duplicateCredentialID.CredentialID = append([]byte(nil), first.CredentialID...)
	if err := store.Create(ctx, duplicateCredentialID); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate credential ID error = %v, want ErrCredentialExists", err)
	}

	usedAt := testNow.Add(time.Hour)
	if err := store.UpdateSignCount(ctx, first.ID, 7, usedAt); err != nil {
		t.Fatalf("UpdateSignCount() error = %v", err)
	}

	got, err = store.GetByCredentialID(ctx, first.CredentialID)
	if err != nil {
		t.Fatalf("GetByCredentialID() after update error = %v", err)
	}

	if got.SignCount != 7 || !got.LastUsedAt.Equal(usedAt) {
		t.Fatalf("updated credential = sign %d, last used %s", got.SignCount, got.LastUsedAt)
	}

	if err := store.UpdateSignCount(ctx, "missing", 1, usedAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSignCount(missing) error = %v, want ErrNotFound", err)
	}

	if err := store.Delete(ctx, second.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if err := store.Delete(ctx, second.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrNotFound", err)
	}

	if _, err := store.GetByCredentialID(ctx, second.CredentialID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByCredentialID(deleted) error = %v, want ErrNotFound", err)
	}

	if err := store.DeleteByUser(ctx, "admin"); err != nil {
		t.Fatalf("DeleteByUser() error = %v", err)
	}

	records, err = store.ListByUser(ctx, "admin")
	if err != nil {
		t.Fatalf("ListByUser() after delete error = %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("ListByUser() after delete = %d records, want 0", len(records))
	}

	if _, err := store.GetByCredentialID(ctx, other.CredentialID); err != nil {
		t.Fatalf("other user's credential was deleted: %v", err)
	}
}

func TestRecoveryCodeConsumeIsAtomic(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	hash := hashRecoveryCode("ABCDEFGH12345678")

	if err := store.ReplaceRecoveryCodes(ctx, "admin", [][]byte{hash}, testNow); err != nil {
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

			ok, err := store.ConsumeRecoveryCode(ctx, "admin", hash, testNow)
			if err != nil {
				t.Errorf("ConsumeRecoveryCode() error = %v", err)
				return
			}

			if ok {
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
}

func TestCredentialValidateBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Credential)
	}{
		{name: "missing record id", mutate: func(c *Credential) { c.ID = "" }},
		{name: "missing user", mutate: func(c *Credential) { c.UserID = "" }},
		{name: "missing credential id", mutate: func(c *Credential) { c.CredentialID = nil }},
		{name: "oversized credential id", mutate: func(c *Credential) {
			c.CredentialID = make([]byte, MaxCredentialIDLen+1)
		}},
		{name: "missing public key", mutate: func(c *Credential) { c.PublicKey = nil }},
		{name: "oversized public key", mutate: func(c *Credential) {
			c.PublicKey = make([]byte, MaxPublicKeyLen+1)
		}},
		{name: "bad aaguid", mutate: func(c *Credential) { c.AAGUID = []byte{1} }},
		{name: "missing name", mutate: func(c *Credential) { c.Name = "" }},
		{name: "too many transports", mutate: func(c *Credential) {
			c.Transports = make([]string, 11)
			for i := range c.Transports {
				c.Transports[i] = "internal"
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credential := testCredential("admin", 9)
			test.mutate(credential)

			if err := credential.Validate(); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Validate() error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}
