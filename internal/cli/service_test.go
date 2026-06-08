package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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

	req := httptest.NewRequest(http.MethodGet, "https://cheesewaf.local/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assertAdminSecurityHeaders(t, rr, true)
}

func assertAdminSecurityHeaders(t *testing.T, rr *httptest.ResponseRecorder, wantHSTS bool) {
	t.Helper()
	for name, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=(), payment=()",
	} {
		if got := rr.Header().Get(name); got != want {
			t.Fatalf("header %s = %q, want %q", name, got, want)
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
