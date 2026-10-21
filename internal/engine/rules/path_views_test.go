package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestEngineURIRulesRetainMatrixRawAndNormalizedViews(t *testing.T) {
	for _, tc := range []struct{ name, pattern, target string }{
		{"matrix view", `^/admin/panel$`, "/admin;v=1/panel"},
		{"matrix and clean", `^/admin/panel$`, "/public/../admin;v=1/panel"},
		{"matrix before dot collapse", `^/admin/panel$`, "/public/.;v=1/../admin/panel"},
		{"encoded matrix before dot collapse", `^/admin/panel$`, "/public/.%3bv=1/../admin/panel"},
		{"legacy matrix spelling", `^/admin;v=1/panel$`, "/admin;v=1/panel"},
		{"legacy clean spelling", `^/admin;v=1/panel$`, "/public/../admin;v=1/panel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := FromConfig([]config.CustomRuleConfig{{
				ID: "admin", Pattern: tc.pattern, Location: "uri", Action: "block", Enabled: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://example.test"+tc.target+"?debug=1", nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			before := req.URL.RequestURI()
			got, err := New(compiled).Detect(context.Background(), reqCtx)
			if err != nil || got == nil || !got.Detected || got.Action != engine.ActionBlock {
				t.Fatalf("configured URI view was lost: result=%#v err=%v normalized=%q", got, err, reqCtx.NormalizedPath)
			}
			if req.URL.RequestURI() != before {
				t.Fatalf("rule changed transport URI: got %q want %q", req.URL.RequestURI(), before)
			}
		})
	}
}

func TestEngineURIMatrixSupportKeepsExistingCleanedPathMeaning(t *testing.T) {
	for _, target := range []string{"/public/../admin/panel", "/public/../admin;v=1/panel"} {
		compiled, err := FromConfig([]config.CustomRuleConfig{{
			ID: "wire-only", Pattern: `^/public/\.\./admin`, Location: "uri", Action: "block", Enabled: true,
		}})
		if err != nil {
			t.Fatal(err)
		}
		reqCtx, err := engine.NewRequestContext(httptest.NewRequest(http.MethodGet, "https://example.test"+target, nil), "default")
		if err != nil {
			t.Fatal(err)
		}
		got, err := New(compiled).Detect(context.Background(), reqCtx)
		if err != nil || got != nil && got.Detected {
			t.Fatalf("matrix support changed existing cleaned path semantics for %q: result=%#v err=%v", target, got, err)
		}
	}
}

func TestEngineRequestURIStillUsesWireTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/admin;v=1/panel?debug=1", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	views := new(requestViews)
	got := views.variants(Rule{Location: "request_uri"}, reqCtx)
	if len(got) != 1 || got[0] != "/admin;v=1/panel?debug=1" {
		t.Fatalf("request_uri did not retain wire target: %#v", got)
	}
}
