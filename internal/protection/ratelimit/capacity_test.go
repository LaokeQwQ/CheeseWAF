package ratelimit

import (
	"strconv"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestLimiterCapacityPreservesLiveQuotas(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := New(config.RateLimitProfile{Requests: 2, Window: time.Minute}, true)
	limiter.now = func() time.Time { return now }
	// One shard makes the capacity boundary deterministic without depending on
	// which client hashes collide in a particular fill sequence.
	limiter.shards = []limiterShard{{keys: map[string]*bucket{}}}
	limiter.WithMaxKeys(64)
	for i := 0; i < 64; i++ {
		if !limiter.Allow("client-" + strconv.Itoa(i)) {
			t.Fatalf("client %d was denied before capacity", i)
		}
	}
	if limiter.Allow("new-client") {
		t.Fatal("new client was admitted by discarding a live quota")
	}
	if limiter.KeyCount() != 64 {
		t.Fatal("capacity denial changed the live bucket count")
	}
	for i := 0; i < 64; i++ {
		key := "client-" + strconv.Itoa(i)
		if !limiter.Allow(key) {
			t.Fatalf("capacity pressure removed remaining quota for %s", key)
		}
		if limiter.Allow(key) {
			t.Fatalf("capacity pressure reset consumed quota for %s", key)
		}
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("new-client") {
		t.Fatal("expired quotas did not make room for a new client")
	}
}

func TestLimiterCapacityPressureDoesNotResetExhaustedClient(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := New(config.RateLimitProfile{Requests: 1, Window: time.Minute}, true)
	limiter.now = func() time.Time { return now }
	limiter.shards = []limiterShard{{keys: map[string]*bucket{}}}
	limiter.WithMaxKeys(64)
	for i := 0; i < 64; i++ {
		if !limiter.Allow("client-" + strconv.Itoa(i)) {
			t.Fatalf("client %d was denied before capacity", i)
		}
	}
	for i := 0; i < 128; i++ {
		if limiter.Allow("overflow-" + strconv.Itoa(i)) {
			t.Fatal("new identity bypassed full live capacity")
		}
	}
	for i := 0; i < 64; i++ {
		if limiter.Allow("client-" + strconv.Itoa(i)) {
			t.Fatalf("consumed quota for client %d was reset", i)
		}
	}
}

func TestLimiterCapacityReclaimsSparseExpiredBucket(t *testing.T) {
	const trials = 64
	denied := 0
	for trial := 0; trial < trials; trial++ {
		now := time.Unix(1_700_000_000, 0)
		limiter := New(config.RateLimitProfile{Requests: 1, Window: time.Minute}, true)
		limiter.now = func() time.Time { return now }
		limiter.shards = []limiterShard{{keys: map[string]*bucket{}}}
		limiter.WithMaxKeys(256)
		if !limiter.Allow("expired") {
			t.Fatal("first window denied")
		}
		now = now.Add(30 * time.Second)
		for i := 0; i < 255; i++ {
			if !limiter.Allow("live-" + strconv.Itoa(i)) {
				t.Fatal("live client denied before capacity")
			}
		}
		now = now.Add(30 * time.Second)
		if !limiter.Allow("replacement") {
			denied++
		}
		if limiter.Allow("live-0") {
			t.Fatal("expired-slot admission reset a live quota")
		}
	}
	if denied != 0 {
		t.Fatalf("denied %d/%d admissions despite an expired capacity slot", denied, trials)
	}
}

func TestLimiterRenewalKeepsOneExpiryPerBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := New(config.RateLimitProfile{Requests: 2, Window: time.Second}, true)
	limiter.now = func() time.Time { return now }
	limiter.shards = []limiterShard{{keys: map[string]*bucket{}}}
	limiter.WithMaxKeys(64)
	for round := 0; round < 20; round++ {
		now = now.Add(2 * time.Second)
		for i := 0; i < 4*evictionBudget; i++ {
			if !limiter.Allow("client-" + strconv.Itoa(i)) {
				t.Fatalf("round %d client %d renewal was denied", round, i)
			}
		}
		sh := &limiter.shards[0]
		if len(sh.expirations) != len(sh.keys) {
			t.Fatalf("expiry records=%d, buckets=%d", len(sh.expirations), len(sh.keys))
		}
		for index, b := range sh.expirations {
			if b.heapIndex != index || sh.keys[b.key] != b {
				t.Fatalf("expiry record %d is not the bucket's current indexed record", index)
			}
		}
		if !limiter.Allow("client-0") || limiter.Allow("client-0") {
			t.Fatal("renewal changed the fixed-window quota")
		}
	}
}

func TestLimiterRenewsExpiredBucketBeyondCleanupBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := New(config.RateLimitProfile{Requests: 1, Window: time.Second}, true)
	limiter.now = func() time.Time { return now }
	limiter.shards = []limiterShard{{keys: map[string]*bucket{}}}
	limiter.WithMaxKeys(64)
	for i := 0; i < 4*evictionBudget; i++ {
		if !limiter.Allow("client-" + strconv.Itoa(i)) {
			t.Fatal("initial admission denied")
		}
		now = now.Add(time.Millisecond)
	}
	key := "client-" + strconv.Itoa(4*evictionBudget-1)
	sh := &limiter.shards[0]
	original := sh.keys[key]
	now = now.Add(2 * time.Second)
	if !limiter.Allow(key) {
		t.Fatal("expired existing key was not renewed")
	}
	if sh.keys[key] != original {
		t.Fatal("renewal replaced a bucket still indexed past the cleanup budget")
	}
	if len(sh.expirations) != len(sh.keys) {
		t.Fatal("renewal left a stale expiry record")
	}
	limiter.expireLocked(sh, now)
	if sh.keys[key] != original || limiter.Allow(key) {
		t.Fatal("later cleanup removed or reset the renewed live quota")
	}
}
