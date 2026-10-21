package apisec

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRateLimiterCapacityPreservesLiveQuotas(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "api", Enabled: true, Requests: 2, Window: time.Minute, PathPattern: "^/api$",
	}})
	if err != nil {
		t.Fatal(err)
	}
	limiter.now = func() time.Time { return now }
	limiter.maxKeys = 2
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	for _, key := range []string{"first", "second"} {
		if !limiter.Allow(req, key) {
			t.Fatalf("%s was denied before capacity", key)
		}
	}
	if limiter.Allow(req, "overflow") {
		t.Fatal("new client was admitted by discarding a live quota")
	}
	for _, key := range []string{"first", "second"} {
		if !limiter.Allow(req, key) || limiter.Allow(req, key) {
			t.Fatalf("capacity pressure changed the remaining quota for %s", key)
		}
	}
	if limiter.KeyCount() != 2 {
		t.Fatal("capacity pressure changed the live bucket count")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow(req, "overflow") {
		t.Fatal("expired quotas did not make room for a new client")
	}
}

func TestRateLimiterCapacityUsesEachRuleWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{
		{ID: "long", Enabled: true, Requests: 1, Window: 2 * time.Hour, PathPattern: "^/long$"},
		{ID: "short", Enabled: true, Requests: 1, Window: time.Minute, PathPattern: "^/short$"},
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter.now = func() time.Time { return now }
	limiter.maxKeys = 2
	longReq := httptest.NewRequest(http.MethodGet, "/long", nil)
	shortReq := httptest.NewRequest(http.MethodGet, "/short", nil)
	if !limiter.Allow(longReq, "long-client") || !limiter.Allow(shortReq, "short-client") {
		t.Fatal("initial requests were denied")
	}
	now = now.Add(time.Hour)
	if limiter.Allow(longReq, "long-client") {
		t.Fatal("one-hour cleanup reset a live two-hour quota")
	}
	if !limiter.Allow(shortReq, "new-client") {
		t.Fatal("expired short window was not reclaimed at capacity")
	}
	if limiter.Allow(longReq, "long-client") {
		t.Fatal("short-window admission evicted the live long-window quota")
	}
	now = now.Add(time.Hour)
	if !limiter.Allow(longReq, "long-client") {
		t.Fatal("long quota did not reset at its configured deadline")
	}
}

func TestRateLimiterExpiredCleanupWorkIsBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "api", Enabled: true, Requests: 1, Window: time.Second, PathPattern: "^/api$",
	}})
	if err != nil {
		t.Fatal(err)
	}
	limiter.now = func() time.Time { return now }
	limiter.maxKeys = 4 * evictionBudget
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	for i := 0; i < limiter.maxKeys; i++ {
		if !limiter.Allow(req, "client-"+strconv.Itoa(i)) {
			t.Fatalf("client %d was denied before capacity", i)
		}
	}
	now = now.Add(2 * time.Second)
	before := limiter.KeyCount()
	if !limiter.Allow(req, "new-client") {
		t.Fatal("new client was denied despite expired capacity")
	}
	after := limiter.KeyCount()
	if removed := before + 1 - after; removed < 1 || removed > evictionBudget {
		t.Fatalf("one request cleaned %d buckets, want 1..%d", removed, evictionBudget)
	}
}

func TestRateLimiterCapacityReclaimsSparseExpiredBucket(t *testing.T) {
	const trials = 64
	denied := 0
	for trial := 0; trial < trials; trial++ {
		now := time.Unix(1_700_000_000, 0)
		limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{
			{ID: "long", Enabled: true, Requests: 1, Window: time.Hour, PathPattern: "^/long$"},
			{ID: "short", Enabled: true, Requests: 1, Window: time.Second, PathPattern: "^/short$"},
		})
		if err != nil {
			t.Fatal(err)
		}
		limiter.now = func() time.Time { return now }
		limiter.maxKeys = 256
		longReq := httptest.NewRequest(http.MethodGet, "/long", nil)
		shortReq := httptest.NewRequest(http.MethodGet, "/short", nil)
		for i := 0; i < limiter.maxKeys-1; i++ {
			if !limiter.Allow(longReq, "live-"+strconv.Itoa(i)) {
				t.Fatal("live client denied before capacity")
			}
		}
		if !limiter.Allow(shortReq, "expired") {
			t.Fatal("short window denied before capacity")
		}
		now = now.Add(2 * time.Second)
		// Exactly one slot is due. Admission must find it regardless of where
		// map iteration starts; checking eight unrelated live buckets is not enough.
		if !limiter.Allow(shortReq, "replacement") {
			denied++
		}
		if limiter.Allow(longReq, "live-0") {
			t.Fatal("expired-slot admission reset a live quota")
		}
	}
	if denied != 0 {
		t.Fatalf("denied %d/%d admissions despite an expired capacity slot", denied, trials)
	}
}

func TestRateLimiterRenewalKeepsOneExpiryPerBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "api", Enabled: true, Requests: 2, Window: time.Second, PathPattern: "^/api$",
	}})
	if err != nil {
		t.Fatal(err)
	}
	limiter.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	for round := 0; round < 20; round++ {
		now = now.Add(2 * time.Second)
		for i := 0; i < 4*evictionBudget; i++ {
			if !limiter.Allow(req, "client-"+strconv.Itoa(i)) {
				t.Fatalf("round %d client %d renewal was denied", round, i)
			}
		}
		if len(limiter.expirations) != len(limiter.hits) {
			t.Fatalf("expiry records=%d, buckets=%d", len(limiter.expirations), len(limiter.hits))
		}
		for index, b := range limiter.expirations {
			if b.heapIndex != index || limiter.hits[b.key] != b {
				t.Fatalf("expiry record %d is not the bucket's current indexed record", index)
			}
		}
		if !limiter.Allow(req, "client-0") || limiter.Allow(req, "client-0") {
			t.Fatal("renewal changed the fixed-window quota")
		}
	}
}

func TestRateLimiterRenewsExpiredBucketBeyondCleanupBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "api", Enabled: true, Requests: 1, Window: time.Second, PathPattern: "^/api$",
	}})
	if err != nil {
		t.Fatal(err)
	}
	limiter.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	for i := 0; i < 4*evictionBudget; i++ {
		if !limiter.Allow(req, "client-"+strconv.Itoa(i)) {
			t.Fatal("initial admission denied")
		}
		now = now.Add(time.Millisecond)
	}
	key := "client-" + strconv.Itoa(4*evictionBudget-1)
	original := limiter.hits["api|"+key]
	now = now.Add(2 * time.Second)
	if !limiter.Allow(req, key) {
		t.Fatal("expired existing key was not renewed")
	}
	if limiter.hits["api|"+key] != original {
		t.Fatal("renewal replaced a bucket still indexed past the cleanup budget")
	}
	if len(limiter.expirations) != len(limiter.hits) {
		t.Fatal("renewal left a stale expiry record")
	}
	limiter.expireLocked(now)
	if limiter.hits["api|"+key] != original || limiter.Allow(req, key) {
		t.Fatal("later cleanup removed or reset the renewed live quota")
	}
}
