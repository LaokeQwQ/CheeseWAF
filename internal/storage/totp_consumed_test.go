package storage

import (
	"context"
	"path/filepath"
	"sync"
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

func TestTOTPConsumedAtomicConsumeAllowsExpiredReuse(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "totp-atomic.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	expires := now.Add(120 * time.Second)
	consumed, err := store.ConsumeTOTP(ctx, "user-1", 123, expires, now)
	if err != nil {
		t.Fatalf("first atomic consume: %v", err)
	}
	if !consumed {
		t.Fatal("first atomic consume must succeed")
	}
	consumed, err = store.ConsumeTOTP(ctx, "user-1", 123, expires, now)
	if err != nil {
		t.Fatalf("second atomic consume: %v", err)
	}
	if consumed {
		t.Fatal("active counter must not be consumed twice")
	}

	later := expires.Add(time.Nanosecond)
	consumed, err = store.ConsumeTOTP(ctx, "user-1", 123, later.Add(120*time.Second), later)
	if err != nil {
		t.Fatalf("expired atomic consume: %v", err)
	}
	if !consumed {
		t.Fatal("expired counter must be consumable again")
	}
}

func TestSQLiteAtomicConsumeAllowsOnlyOneIndependentConsumer(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "totp-concurrent.db")
	first, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open first sqlite: %v", err)
	}
	defer first.Close()
	second, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open second sqlite: %v", err)
	}
	defer second.Close()
	if err := first.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	start := make(chan struct{})
	results := make(chan bool, 2)
	var wg sync.WaitGroup
	for _, store := range []*SQLiteStore{first, second} {
		wg.Add(1)
		go func(store *SQLiteStore) {
			defer wg.Done()
			<-start
			consumed, err := store.ConsumeTOTP(ctx, "user-1", 123, now.Add(120*time.Second), now)
			if err != nil {
				t.Errorf("concurrent atomic consume: %v", err)
				return
			}
			results <- consumed
		}(store)
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for consumed := range results {
		if consumed {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent atomic consume successes=%d, want exactly 1", successes)
	}
}
