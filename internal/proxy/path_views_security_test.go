package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/rules"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
)

func TestPathViewsAuthenticationRejectsBeforeBodyRead(t *testing.T) {
	for _, path := range []string{"//api/private", "/api/x/../private", "/api;v=1/private", "/%2561pi/private"} {
		t.Run(path, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/unused$", "/target", func(cfg *config.Config) {
				cfg.APISec.Auth.Enabled = true
				cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
				cfg.APISec.Auth.JWTSharedSecret = "path-views-secret"
			})
			body := &apiSecurityReadTrackingBody{reader: bytes.NewReader([]byte("unread payload"))}
			req := rewritePolicyRequest(path)
			req.Body, req.ContentLength = body, -1
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || calls.Load() != 0 || body.reads != 0 {
				t.Fatalf("auth path=%q status=%d upstream=%d body reads=%d", path, rec.Code, calls.Load(), body.reads)
			}
		})
	}
}

func TestPathViewsSchemaChecksEveryRoutingSpelling(t *testing.T) {
	for _, path := range []string{"/api/search", "//api/search", "/api/x/../search", "/api;v=1/search"} {
		t.Run(path, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/unused$", "/target", func(cfg *config.Config) {
				cfg.APISec.Validation.Enabled = true
				cfg.APISec.Validation.Schemas = []config.APIEndpointSchemaConfig{{
					ID: "search", Enabled: true, Method: http.MethodPost, PathPattern: "^/api/search$", RequiredParams: []string{"q"},
				}}
			})
			missing := httptest.NewRecorder()
			server.Handler().ServeHTTP(missing, rewritePolicyRequest(path))
			if missing.Code != http.StatusBadRequest || calls.Load() != 0 {
				t.Fatalf("schema path=%q status=%d upstream=%d", path, missing.Code, calls.Load())
			}
			valid := httptest.NewRecorder()
			server.Handler().ServeHTTP(valid, rewritePolicyRequest(path+"?q=present"))
			if valid.Code != http.StatusNoContent || calls.Load() != 1 || valid.Header().Get("X-Upstream-URI") != path+"?q=present" {
				t.Fatalf("valid schema path changed: status=%d upstream=%d uri=%q", valid.Code, calls.Load(), valid.Header().Get("X-Upstream-URI"))
			}
		})
	}
}

func TestPathViewsRateLimitSharesOneEndpointBudget(t *testing.T) {
	server, calls := newRewritePolicyTestServer(t, "^/unused$", "/target", func(cfg *config.Config) {
		cfg.APISec.RateLimits = []config.APIEndpointLimitConfig{{
			ID: "upload", Enabled: true, Method: http.MethodPost, PathPattern: "^/api/upload$", Requests: 2, Window: time.Minute,
		}}
	})
	for _, path := range []string{"/api/upload", "//api/upload"} {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, rewritePolicyRequest(path))
		if rec.Code != http.StatusNoContent || rec.Header().Get("X-Upstream-URI") != path {
			t.Fatalf("within-budget path=%q status=%d uri=%q", path, rec.Code, rec.Header().Get("X-Upstream-URI"))
		}
	}
	body := &apiSecurityReadTrackingBody{reader: bytes.NewReader([]byte("unread payload"))}
	req := rewritePolicyRequest("/api;v=1/upload")
	req.Body, req.ContentLength = body, -1
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || calls.Load() != 2 || body.reads != 0 {
		t.Fatalf("endpoint budget escaped: status=%d upstream=%d body reads=%d", rec.Code, calls.Load(), body.reads)
	}
}

func TestPathViewsRejectMatrixParentBeforeUpstream(t *testing.T) {
	for _, path := range []string{"/api/x/..;/private", "/..%3b/private", "/a/%252e%252e%253b/private"} {
		t.Run(path, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/unused$", "/target", nil)
			body := &apiSecurityReadTrackingBody{reader: bytes.NewReader([]byte("unread payload"))}
			req := rewritePolicyRequest(path)
			req.Body, req.ContentLength = body, -1
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || calls.Load() != 0 || body.reads != 0 {
				t.Fatalf("matrix parent path=%q status=%d upstream=%d body reads=%d", path, rec.Code, calls.Load(), body.reads)
			}
		})
	}
	server, calls := newRewritePolicyTestServer(t, "^/original$", "/a/..;/private", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, rewritePolicyRequest("/original"))
	if rec.Code != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("invalid rewritten target reached upstream: status=%d upstream=%d", rec.Code, calls.Load())
	}
}

func TestPathViewsPreserveOrdinaryMatrixURIAndBody(t *testing.T) {
	server, _ := newRewriteWAFServer(t, "/unused", engine.NewPipeline(), nil)
	const path = "/store;version=1/items;region=cn?view=raw%2Fkeep"
	const body = "ordinary;body=value&literal=%252F"
	req := httptest.NewRequest(http.MethodPost, "http://localhost"+path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Upstream-URI") != path || rec.Body.String() != body {
		t.Fatalf("ordinary matrix request changed: status=%d uri=%q body=%q", rec.Code, rec.Header().Get("X-Upstream-URI"), rec.Body.String())
	}
}

func TestPathViewsACLRetainsLiteralAndRoutingDenies(t *testing.T) {
	for _, prefix := range []string{"/admin;v=1", "/admin"} {
		t.Run(prefix, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/unused$", "/target", func(cfg *config.Config) {
				cfg.Protection.ACL.Enabled = true
				cfg.Protection.ACL.Rules = []config.ACLRuleConfig{{ID: "matrix-admin", Enabled: true, PathPrefix: prefix, Action: "block"}}
			})
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, rewritePolicyRequest("/admin;v=1/panel"))
			if rec.Code != http.StatusForbidden || calls.Load() != 0 {
				t.Fatalf("ACL prefix=%q escaped: status=%d upstream=%d", prefix, rec.Code, calls.Load())
			}
		})
	}
}

func TestPathViewsCustomURIRetainsLiteralAndRoutingDenies(t *testing.T) {
	for _, pattern := range []string{`^/admin;v=1/panel$`, `^/admin/panel$`} {
		t.Run(pattern, func(t *testing.T) {
			detector := rules.New([]rules.Rule{{ID: "matrix-uri", Enabled: true, Location: "uri", Pattern: regexp.MustCompile(pattern), Action: engine.ActionBlock, Severity: engine.SeverityHigh}})
			server, _ := newRewriteWAFServer(t, "/unused", engine.NewPipeline(detector), nil)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/admin;v=1/panel", nil))
			if rec.Code != http.StatusForbidden || rec.Header().Get("X-Upstream-URI") != "" {
				t.Fatalf("custom URI pattern=%q escaped: status=%d upstream=%q", pattern, rec.Code, rec.Header().Get("X-Upstream-URI"))
			}
		})
	}
}

func TestPathViewsDoNotExpandSemanticAllowlist(t *testing.T) {
	analyzer := semantic.NewAnalyzer("block", 3)
	analyzer.SetAllowlists([]string{"/health"}, nil)
	server, _ := newRewriteWAFServer(t, "/unused", engine.NewPipeline(analyzer), nil)
	query := "?id=" + url.QueryEscape("1 UNION SELECT password FROM users")
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/health", http.StatusOK},
		{"/health;v=1", http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost"+tc.path+query, nil))
		if rec.Code != tc.want {
			t.Fatalf("semantic allowlist path=%q status=%d want=%d", tc.path, rec.Code, tc.want)
		}
		if tc.want == http.StatusForbidden && rec.Header().Get("X-Upstream-URI") != "" {
			t.Fatal("non-allowlisted matrix request reached upstream")
		}
	}
}

func TestPathViewsRequireIPAllowOnEveryInterpretation(t *testing.T) {
	server, calls := newRewritePolicyTestServer(t, "^/unused$", "/target", func(cfg *config.Config) {
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
		cfg.APISec.Auth.JWTSharedSecret = "path-views-secret"
		cfg.Protection.IP.AccessRules = []config.IPAccessRuleConfig{{
			ID: "literal-only", Enabled: true, Action: "allow", Scope: "path", PathPrefix: "/api;v=1", Entries: []string{"203.0.113.10"},
		}}
	})
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, rewritePolicyRequest("/api;v=1/private"))
	if rec.Code != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("one interpretation's IP allow skipped auth: status=%d upstream=%d", rec.Code, calls.Load())
	}
}
