package handler

import (
	"fmt"
	"testing"
	"time"
)

func TestSimpleRateLimiterEnforcesCapacityAndResetsWindow(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()
	limiter := newSimpleRateLimiter(time.Minute, 2)

	if !limiter.Allow("node-a", now) || !limiter.Allow("node-a", now.Add(time.Second)) {
		t.Fatal("first two requests in the window should be allowed")
	}
	if limiter.Allow("node-a", now.Add(2*time.Second)) {
		t.Fatal("request above the per-key capacity should be rejected")
	}
	if !limiter.Allow("node-a", now.Add(62*time.Second)) {
		t.Fatal("capacity should reset after the window elapses")
	}
}

func TestSimpleRateLimiterBoundsUniqueKeysAndEvictsInConstantTimeOrder(t *testing.T) {
	now := time.Unix(2_000, 0).UTC()
	limiter := newSimpleRateLimiter(time.Minute, 1)
	limiter.maxKeys = 64

	for i := 0; i < 10_000; i++ {
		if !limiter.Allow(fmt.Sprintf("node-%05d", i), now) {
			t.Fatalf("first request for key %d should be allowed", i)
		}
	}
	if got := len(limiter.buckets); got != limiter.maxKeys {
		t.Fatalf("bucket count = %d, want hard cap %d", got, limiter.maxKeys)
	}
	if got := limiter.order.Len(); got != limiter.maxKeys {
		t.Fatalf("LRU entry count = %d, want hard cap %d", got, limiter.maxKeys)
	}
	if _, ok := limiter.buckets["node-00000"]; ok {
		t.Fatal("oldest unique key should have been evicted")
	}
	if _, ok := limiter.buckets["node-09999"]; !ok {
		t.Fatal("most recent unique key should remain tracked")
	}
}

func TestSimpleRateLimiterPrunesExpiredBucketsFromLRUTail(t *testing.T) {
	now := time.Unix(3_000, 0).UTC()
	limiter := newSimpleRateLimiter(time.Minute, 1)
	limiter.maxKeys = 8
	for i := 0; i < limiter.maxKeys; i++ {
		limiter.Allow(fmt.Sprintf("old-%d", i), now)
	}

	if !limiter.Allow("fresh", now.Add(2*time.Minute+time.Second)) {
		t.Fatal("fresh key should be allowed")
	}
	if got := len(limiter.buckets); got != 1 {
		t.Fatalf("expired buckets were not pruned: got %d buckets", got)
	}
}
