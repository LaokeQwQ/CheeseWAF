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
