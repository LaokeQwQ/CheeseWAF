package apisec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRateLimiterMatchesRequestIdentitiesWithoutDoubleCharging(t *testing.T) {
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{
		{ID: "public", Enabled: true, Method: http.MethodGet, PathPattern: "^/public$", Requests: 2, Window: time.Minute},
		{ID: "target", Enabled: true, Method: http.MethodGet, PathPattern: "^/private$", Requests: 2, Window: time.Minute},
		{ID: "shared", Enabled: true, Method: http.MethodGet, PathPattern: "^/(public|private)$", Requests: 2, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/public", nil),
		httptest.NewRequest(http.MethodGet, "/private", nil),
		httptest.NewRequest(http.MethodGet, "/public?rewritten=1", nil),
	}
	for n, want := range []bool{true, true, false} {
		if got := limiter.AllowRequests(requests, "client"); got != want {
			t.Fatalf("request %d allowed=%v, want %v", n+1, got, want)
		}
	}
	for _, id := range []string{"public", "target", "shared"} {
		if got := limiter.hits[id+"|client"].count; got != 2 {
			t.Fatalf("rule %q counted %d requests, want 2", id, got)
		}
	}
}

func TestRateLimiterRequestIdentitiesPreserveMethodAndEmptySemantics(t *testing.T) {
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{
		{ID: "post", Enabled: true, Method: http.MethodPost, PathPattern: "^/private$", Requests: 1, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !limiter.AllowRequests([]*http.Request{nil, httptest.NewRequest(http.MethodGet, "/private", nil)}, "client") {
		t.Fatal("nonmatching method must not consume or deny a request")
	}
	if limiter.KeyCount() != 0 {
		t.Fatal("nonmatching method created a rate bucket")
	}
	if !limiter.AllowRequests(nil, "client") || !limiter.AllowRequests([]*http.Request{nil}, "client") {
		t.Fatal("empty request identities must preserve Allow(nil) behavior")
	}
	post := httptest.NewRequest(http.MethodPost, "/private", nil)
	if !limiter.Allow(post, "client") || limiter.AllowRequests([]*http.Request{post}, "client") {
		t.Fatal("Allow and AllowRequests did not share the same rule budget")
	}
}
