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
