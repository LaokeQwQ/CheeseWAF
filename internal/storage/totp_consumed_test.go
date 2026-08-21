package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestTOTPConsumedPersistence(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "totp.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	expires := now.Add(120 * time.Second)
	if err := store.MarkTOTPConsumed(ctx, "user-1", 123, expires); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}

	// Within the TTL the counter is still considered used.
	used, err := store.IsTOTPConsumed(ctx, "user-1", 123, now)
	if err != nil {
		t.Fatalf("is consumed: %v", err)
	}
	if !used {
		t.Fatal("expected counter to be consumed within TTL")
	}

	// After the TTL the same counter is no longer blocked.
	used, err = store.IsTOTPConsumed(ctx, "user-1", 123, expires.Add(time.Second))
	if err != nil {
		t.Fatalf("is consumed after ttl: %v", err)
	}
	if used {
		t.Fatal("expected counter to be reusable after TTL expiry")
	}

	// Deleting the record also unblocks the counter before TTL.
	if err := store.DeleteTOTPConsumed(ctx, "user-1", 123); err != nil {
		t.Fatalf("delete consumed: %v", err)
	}
	used, err = store.IsTOTPConsumed(ctx, "user-1", 123, now)
	if err != nil {
		t.Fatalf("is consumed after delete: %v", err)
	}
	if used {
		t.Fatal("expected delete to unblock counter")
	}
}
