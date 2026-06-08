package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAdminHandlerServesSPAAndKeepsAPI(t *testing.T) {
	webDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("cheesewaf-ui"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	assets := filepath.Join(webDir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assets, "app.js"), []byte("console.log('cw')"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	t.Setenv("CHEESEWAF_WEB_DIR", webDir)

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	})
	handler := adminHandler(&config.Config{}, apiHandler)

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/", want: "cheesewaf-ui"},
		{path: "/sites/default", want: "cheesewaf-ui"},
		{path: "/assets/app.js", want: "console.log('cw')"},
		{path: "/api/system", want: "api:/api/system"},
		{path: "/health", want: "api:/health"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Body.String() != tc.want {
			t.Fatalf("%s: got %q want %q", tc.path, rr.Body.String(), tc.want)
		}
		assertAdminSecurityHeaders(t, rr, false)
	}

	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rrMetrics := httptest.NewRecorder()
	handler.ServeHTTP(rrMetrics, reqMetrics)
	if rrMetrics.Code != http.StatusNotFound {
		t.Fatalf("/metrics should not fall back to SPA when public metrics are disabled, got %d: %s", rrMetrics.Code, rrMetrics.Body.String())
	}
	assertAdminSecurityHeaders(t, rrMetrics, false)

	publicMetricsHandler := adminHandler(&config.Config{Monitor: config.MonitorConfig{Prometheus: config.PrometheusConfig{Enabled: true, Path: "/metrics", Public: true}}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("metrics:" + r.URL.Path))
	}))
	rrPublicMetrics := httptest.NewRecorder()
	publicMetricsHandler.ServeHTTP(rrPublicMetrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rrPublicMetrics.Body.String() != "metrics:/metrics" {
		t.Fatalf("public /metrics should route to api handler, got %q", rrPublicMetrics.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "https://cheesewaf.local/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assertAdminSecurityHeaders(t, rr, true)
}

func assertAdminSecurityHeaders(t *testing.T, rr *httptest.ResponseRecorder, wantHSTS bool) {
	t.Helper()
	for name, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=()",
	} {
		if got := rr.Header().Get(name); got != want {
			t.Fatalf("header %s = %q, want %q", name, got, want)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"connect-src 'self' ws: wss:",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("Content-Security-Policy %q does not contain %q", csp, want)
		}
	}
	hsts := rr.Header().Get("Strict-Transport-Security")
	if wantHSTS && hsts == "" {
		t.Fatal("expected HSTS on HTTPS admin response")
	}
	if !wantHSTS && hsts != "" {
		t.Fatalf("did not expect HSTS on HTTP admin response, got %q", hsts)
	}
}

func TestBuildPipelineHonorsNoSQLSemanticSwitch(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{
				ID:      "default",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: config.SemanticEngineSwitches{
						NoSQL: true,
					},
				},
			},
		},
	}
	pipeline, err := buildPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":{"$ne":null},"password":{"$ne":null}}`))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pipeline.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "nosqli" {
		t.Fatalf("expected NoSQLi detection from site semantic switch, got %+v", result)
	}
}

func TestBuildPipelineHonorsSSTISemanticSwitch(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{
				ID:      "default",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: config.SemanticEngineSwitches{
						SSTI: true,
					},
				},
			},
		},
	}
	pipeline, err := buildPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "/profile", bytes.NewBufferString(`display_name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pipeline.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "ssti" {
		t.Fatalf("expected SSTI detection from site semantic switch, got %+v", result)
	}
}
