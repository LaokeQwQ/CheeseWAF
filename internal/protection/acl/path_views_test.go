package acl

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestPolicyEvaluatesMatrixAndLegacyPathViews(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, target, action string
		wantAction                   engine.Action
	}{
		{"matrix block", "/admin", "/admin;v=1/panel", "block", engine.ActionBlock},
		{"matrix challenge", "/admin", "/admin;v=1/panel", "challenge", engine.ActionChallenge},
		{"matrix log", "/admin", "/admin;v=1/panel", "log", engine.ActionLog},
		{"empty matrix segment", "/admin", "/;session=abc/admin/panel", "block", engine.ActionBlock},
		{"encoded matrix", "/admin", "/admin%3bv=1/panel", "block", engine.ActionBlock},
		{"matrix before dot collapse", "/admin", "/public/.;v=1/../admin/panel", "block", engine.ActionBlock},
		{"encoded matrix before dot collapse", "/admin", "/public/.%3bv=1/../admin/panel", "block", engine.ActionBlock},
		{"legacy matrix prefix", "/admin;v=1", "/admin;v=1/panel", "block", engine.ActionBlock},
		{"legacy normalized prefix", "/admin;v=1", "/public/../admin;v=1/panel", "block", engine.ActionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{
				ID: "admin", Method: http.MethodGet, PathPrefix: tc.prefix, Action: tc.action, Enabled: true,
			}}})
			req := httptest.NewRequest(http.MethodGet, "https://example.test"+tc.target+"?view=1", nil)
			before := req.URL.RequestURI()
			result := policy.Evaluate(req)
			if result == nil || result.DetectorID != "acl.admin" || result.Action != tc.wantAction {
				t.Fatalf("path view did not retain the configured rule: %#v", result)
			}
			if req.URL.RequestURI() != before {
				t.Fatalf("policy changed transport URI: got %q want %q", req.URL.RequestURI(), before)
			}
		})
	}
}

func TestPolicyMatrixViewsKeepMethodHeaderAndSegmentBoundaries(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{
		ID: "admin", Method: http.MethodPost, PathPrefix: "/admin", Header: "X-Role", HeaderValue: "operator", Action: "block", Enabled: true,
	}}})
	for _, tc := range []struct{ method, target, role string }{
		{http.MethodGet, "/admin;v=1/panel", "operator"},
		{http.MethodPost, "/admin;v=1/panel", "viewer"},
		{http.MethodPost, "/administrator;v=1/panel", "operator"},
	} {
		req := httptest.NewRequest(tc.method, "https://example.test"+tc.target, nil)
		req.Header.Set("X-Role", tc.role)
		if got := policy.Evaluate(req); got != nil {
			t.Fatalf("unrelated policy conditions were weakened for %+v: %#v", tc, got)
		}
	}
}

func TestPolicyMatrixLogCannotShadowLegacyBlock(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{
		{ID: "matrix-log", PathPrefix: "/admin", Action: "log", Enabled: true},
		{ID: "legacy-block", PathPrefix: "/admin;v=1", Action: "block", Enabled: true},
	}})
	got := policy.Evaluate(httptest.NewRequest(http.MethodGet, "https://example.test/admin;v=1/panel", nil))
	if got == nil || got.DetectorID != "acl.legacy-block" || got.Action != engine.ActionBlock {
		t.Fatalf("new view shadowed the existing block: %#v", got)
	}
}

func TestPolicyMatrixViewsKeepExistingDotPathMeaning(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{
		ID: "admin", PathPrefix: "/admin", Action: "block", Enabled: true,
	}}})
	if got := policy.Evaluate(httptest.NewRequest(http.MethodGet, "https://example.test/admin/../public", nil)); got != nil {
		t.Fatalf("matrix support changed an existing cleaned non-matrix path: %#v", got)
	}
}
