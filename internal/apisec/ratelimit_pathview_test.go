package apisec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func newAdminLimiter(t *testing.T) *RateLimiter {
	t.Helper()
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "admin", Method: "GET", PathPattern: `^/admin`,
		Requests: 1, Window: time.Minute, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return limiter
}

// TestAllowRequestsSharesBudgetAcrossPathViews pins the bypass: the endpoint
// pattern was written against the normalized path, so a request spelled with a
// leading double slash must consume the same budget instead of escaping it.
func TestAllowRequestsSharesBudgetAcrossPathViews(t *testing.T) {
	limiter := newAdminLimiter(t)

	first := httptest.NewRequest("GET", "https://example.test/admin/panel", nil)
	if !limiter.AllowRequests([]*http.Request{first}, "client-1") {
		t.Fatal("first request within budget was denied")
	}

	bypass := httptest.NewRequest("GET", "https://example.test//admin/panel", nil)
	if limiter.AllowRequests([]*http.Request{bypass}, "client-1") {
		t.Fatal("//admin/panel escaped the ^/admin endpoint budget")
	}
}

// TestAllowRequestsKeepsRawPathViewForExistingPatterns is the regression guard
// for the additive matching: patterns written against the raw spelling must not
// stop matching.
func TestAllowRequestsKeepsRawPathViewForExistingPatterns(t *testing.T) {
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "legacy", Method: "GET", PathPattern: `^/legacy;v=1`,
		Requests: 1, Window: time.Minute, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://example.test/legacy;v=1/list", nil)
	if !limiter.AllowRequests([]*http.Request{req}, "client-2") {
		t.Fatal("raw-path pattern stopped matching")
	}
	if limiter.AllowRequests([]*http.Request{req}, "client-2") {
		t.Fatal("raw-path pattern did not consume budget")
	}
}

// TestAllowRequestsDeniesUnnormalizablePath pins the fail-closed choice: a
// path that cannot be normalized has no trustworthy policy view, so it must
// not be granted a budget slot.
func TestAllowRequestsDeniesUnnormalizablePath(t *testing.T) {
	limiter := newAdminLimiter(t)
	req := httptest.NewRequest("GET", "https://example.test/x/..;/y", nil)
	if limiter.AllowRequests([]*http.Request{req}, "client-3") {
		t.Fatal("unnormalizable path must be denied, not granted")
	}
}

// TestAllowRequestsDeductsOnceWhenBothViewsMatch pins single deduction: a path
// that matches the pattern in both the raw and normalized view must consume one
// slot, not two.
func TestAllowRequestsDeductsOnceWhenBothViewsMatch(t *testing.T) {
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{
		ID: "admin", Method: "GET", PathPattern: `^/admin`,
		Requests: 2, Window: time.Minute, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://example.test/admin//panel", nil)
	if !limiter.AllowRequests([]*http.Request{req}, "client-4") {
		t.Fatal("first request within budget was denied")
	}
	if got := limiter.hits["admin|client-4"].count; got != 1 {
		t.Fatalf("budget count=%d, want 1 deduction per request", got)
	}
	if !limiter.AllowRequests([]*http.Request{req}, "client-4") {
		t.Fatal("second request within budget was denied")
	}
	if limiter.AllowRequests([]*http.Request{req}, "client-4") {
		t.Fatal("third request exceeded the budget but was allowed")
	}
}
