package ratelimit

import (
	"strconv"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestLimiterBlocksAfterWindowQuota(t *testing.T) {
	limiter := New(config.RateLimitProfile{Requests: 1, Window: time.Minute, Burst: 1}, true)
	if !limiter.Allow("client") || !limiter.Allow("client") {
		t.Fatal("expected request and burst to pass")
	}
	if limiter.Allow("client") {
		t.Fatal("expected third request to be blocked")
	}
}

func TestLimiterEvictsWhenShardCapReached(t *testing.T) {
	// Tiny cap forces per-shard capacity of 64 still; override maxKeys low via WithMaxKeys
	// and use enough distinct keys that a single shard fills after hash clustering is unlikely.
	// Use maxKeys so perShardCap = 64; fill one key heavily and many others to exercise eviction path.
	limiter := New(config.RateLimitProfile{Requests: 100, Window: time.Minute, Burst: 0}, true).WithMaxKeys(64 * 32)
	// Fill well beyond capacity with unique keys; should not grow unbounded.
	for i := 0; i < 5000; i++ {
		_ = limiter.Allow("ip-" + strconv.Itoa(i))
	}
	if n := limiter.KeyCount(); n > 64*32+32 {
		t.Fatalf("expected key count bounded near maxKeys, got %d", n)
	}
}

func TestLimiterExpiresOldWindows(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// Burst must be >0 (New coerces Burst<=0 to Requests); limit = 1+1 = 2.
	limiter := New(config.RateLimitProfile{Requests: 1, Window: time.Second, Burst: 1}, true)
	limiter.now = func() time.Time { return now }
	if !limiter.Allow("a") || !limiter.Allow("a") {
		t.Fatal("request + burst should pass")
	}
	if limiter.Allow("a") {
		t.Fatal("third should block in window")
	}
	now = now.Add(2 * time.Second)
	if !limiter.Allow("a") {
		t.Fatal("after window should allow again")
	}
}

func TestLimiterShardDistributesKeysAndAllowWorks(t *testing.T) {
	limiter := New(config.RateLimitProfile{Requests: 10, Window: time.Minute, Burst: 0}, true)
	shardSeen := map[*limiterShard]struct{}{}
	for i := 0; i < 64; i++ {
		key := "client-" + strconv.Itoa(i)
		if !limiter.Allow(key) {
			t.Fatalf("expected Allow(%q) to pass", key)
		}
		shardSeen[limiter.shard(key)] = struct{}{}
	}
	if len(shardSeen) < 2 {
		t.Fatalf("expected keys to land on multiple shards, got %d", len(shardSeen))
	}
	// Same key must still share one bucket across calls.
	if !limiter.Allow("client-0") {
		t.Fatal("second Allow on same key should still pass under quota")
	}
}
