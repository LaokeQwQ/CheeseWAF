package bot

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
)

func pendingFixture(owner string, expires time.Time) behaviorPending {
	return behaviorPending{
		path:    "/protected",
		method:  "GET",
		kind:    captcha.BehaviorShapeSlider,
		level:   1,
		owner:   owner,
		peer:    owner,
		expires: expires,
	}
}

func TestBehaviorPendingStoreTTLAndBoundary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(4, 2, func() time.Time { return now })
	if err := store.Add("first", pendingFixture("owner-a", now.Add(time.Minute))); err != nil {
		t.Fatalf("add pending challenge: %v", err)
	}
	now = now.Add(time.Minute)
	if _, ok := store.Claim("first", "owner-a"); ok {
		t.Fatal("challenge must be expired at the exact expiration boundary")
	}
	if got := store.Len(); got != 0 {
		t.Fatalf("expired state remained in store: %d", got)
	}
	if len(store.expirations) != 0 || len(store.ownerPending) != 0 {
		t.Fatalf("expired indexes were not cleaned: heap=%d clients=%d", len(store.expirations), len(store.ownerPending))
	}
}

func TestBehaviorPendingStoreEnforcesAndReleasesQuotas(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(3, 2, func() time.Time { return now })
	expires := now.Add(time.Minute)
	if err := store.Add("a1", pendingFixture("owner-a", expires)); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("a2", pendingFixture("owner-a", expires)); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("a3", pendingFixture("owner-a", expires)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("expected per-owner capacity error, got %v", err)
	}
	if err := store.Add("b1", pendingFixture("owner-b", expires)); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("c1", pendingFixture("owner-c", expires)); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("expected global capacity error, got %v", err)
	}
	if pending, ok := store.Claim("a1", "owner-a"); !ok || pending.owner != "owner-a" {
		t.Fatal("expected atomic consumption of a1")
	}
	if !store.Finalize("a1") {
		t.Fatal("expected claimed challenge to finalize")
	}
	if err := store.Add("a3", pendingFixture("owner-a", expires)); err != nil {
		t.Fatalf("consume did not release owner and global quota: %v", err)
	}
	if !store.Revoke("a2") || store.Revoke("a2") {
		t.Fatal("revoke must succeed exactly once")
	}
	if len(store.expirations) != store.Len() {
		t.Fatalf("heap and entries diverged: heap=%d entries=%d", len(store.expirations), store.Len())
	}
}

func TestBehaviorPendingStoreHundredThousandUnverifiedRemainBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const capacity = 257
	store := newBehaviorPendingStore(capacity, 8, func() time.Time { return now })
	for i := 0; i < 100_000; i++ {
		jti := fmt.Sprintf("challenge-%d", i)
		owner := fmt.Sprintf("owner-%d", i)
		err := store.Add(jti, pendingFixture(owner, now.Add(time.Minute)))
		if i < capacity && err != nil {
			t.Fatalf("unexpected add failure at %d: %v", i, err)
		}
		if i >= capacity && !errors.Is(err, ErrChallengeCapacity) {
			t.Fatalf("expected capacity rejection at %d, got %v", i, err)
		}
	}
	if got := store.Len(); got != capacity {
		t.Fatalf("pending state exceeded or lost capacity: got %d want %d", got, capacity)
	}
	if len(store.expirations) != capacity || len(store.ownerPending) != capacity {
		t.Fatalf("secondary state is unbounded or inconsistent: heap=%d clients=%d", len(store.expirations), len(store.ownerPending))
	}
	now = now.Add(time.Minute)
	if got := store.Len(); got != 0 {
		t.Fatalf("expired pressure state remained: %d", got)
	}
	if len(store.expirations) != 0 || len(store.ownerPending) != 0 {
		t.Fatalf("expired secondary state remained: heap=%d clients=%d", len(store.expirations), len(store.ownerPending))
	}
}

func TestBehaviorPendingStoreConcurrentConsumeExactlyOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(8, 8, func() time.Time { return now })
	if err := store.Add("shared", pendingFixture("owner", now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := store.Claim("shared", "owner"); ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("challenge consumed %d times, want exactly once", got)
	}
	if !store.Finalize("shared") {
		t.Fatal("winning claim was not finalized")
	}
	if store.Len() != 0 || len(store.expirations) != 0 || len(store.ownerPending) != 0 {
		t.Fatal("consumed challenge left residual state")
	}
}

func TestBehaviorPendingStoreReleaseAllowsRetry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(4, 2, func() time.Time { return now })
	if err := store.Add("retry", pendingFixture("client", now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Claim("retry", "client"); !ok {
		t.Fatal("initial claim failed")
	}
	if _, ok := store.Claim("retry", "client"); ok {
		t.Fatal("claimed challenge was concurrently claimable")
	}
	if !store.Release("retry") {
		t.Fatal("release failed")
	}
	if _, ok := store.Claim("retry", "client"); !ok {
		t.Fatal("released challenge could not be retried")
	}
	if !store.Finalize("retry") {
		t.Fatal("retry claim could not be finalized")
	}
}

func TestBehaviorPendingStoreConcurrentMixedOperationsRemainConsistent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(512, 8, func() time.Time { return now })
	for i := 0; i < 512; i++ {
		if err := store.Add(fmt.Sprintf("mixed-%d", i), pendingFixture(fmt.Sprintf("client-%d", i/8), now.Add(time.Duration(i%7+1)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 512; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			jti := fmt.Sprintf("mixed-%d", i)
			switch i % 3 {
			case 0:
				if _, ok := store.Claim(jti, fmt.Sprintf("client-%d", i/8)); ok {
					store.Finalize(jti)
				}
			case 1:
				if _, ok := store.Claim(jti, fmt.Sprintf("client-%d", i/8)); ok {
					store.Release(jti)
				}
			default:
				store.Revoke(jti)
			}
		}()
	}
	wg.Wait()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != len(store.expirations) {
		t.Fatalf("entry and heap counts differ: entries=%d heap=%d", len(store.entries), len(store.expirations))
	}
	counted := 0
	for _, count := range store.ownerPending {
		if count < 1 || count > store.perOwnerCapacity {
			t.Fatalf("invalid client count: %d", count)
		}
		counted += count
	}
	if counted != len(store.entries) {
		t.Fatalf("client counts differ from entries: clients=%d entries=%d", counted, len(store.entries))
	}
	for index, expiry := range store.expirations {
		if expiry == nil || expiry.index != index {
			t.Fatalf("invalid heap index at %d", index)
		}
		entry, ok := store.entries[expiry.jti]
		if !ok || entry.expiry != expiry {
			t.Fatalf("heap entry %q is not linked to the map", expiry.jti)
		}
	}
}

func TestBehaviorPendingStoreSharedNATOwnersAreIsolated(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(32, 2, func() time.Time { return now })
	for _, item := range []struct{ jti, owner string }{{"a1", "browser-a"}, {"a2", "browser-a"}, {"b1", "browser-b"}, {"b2", "browser-b"}} {
		pending := pendingFixture(item.owner, now.Add(time.Minute))
		pending.peer = "site\x00shared-ip"
		if err := store.Add(item.jti, pending); err != nil {
			t.Fatalf("add %s: %v", item.jti, err)
		}
	}
	if _, ok := store.Claim("a1", "browser-b"); ok {
		t.Fatal("other NAT browser claimed foreign pending")
	}
	if _, ok := store.Claim("a1", "browser-a"); !ok {
		t.Fatal("owner could not claim pending after foreign attempt")
	}
}

func TestBehaviorPendingStoreRotatingOwnersCannotBypassPeerQuota(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newBehaviorPendingStore(100, 2, func() time.Time { return now })
	for i := 0; i < store.perPeerCapacity; i++ {
		pending := pendingFixture(fmt.Sprintf("rotated-%d", i), now.Add(time.Minute))
		pending.peer = "site\x00shared-ip"
		if err := store.Add(fmt.Sprintf("jti-%d", i), pending); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	pending := pendingFixture("fresh-owner", now.Add(time.Minute))
	pending.peer = "site\x00shared-ip"
	if err := store.Add("overflow", pending); !errors.Is(err, ErrChallengeCapacity) {
		t.Fatalf("rotated owner bypassed peer quota: %v", err)
	}
}
