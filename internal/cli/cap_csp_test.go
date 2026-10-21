package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

func TestAdminCapCSPUsesCurrentLoginProviderAndExactResourceOrigins(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Enabled = true
	cfg.Console.Login.CAPTCHA.Provider = "cap"
	cfg.CAPTCHAProviders.Cap = config.CapStandaloneConfig{
		APIEndpoint: "https://cap.example.test/site/",
		WidgetURL:   "https://unused-widget.example.test/cap.js",
		WASMURL:     "https://wasm.example.test:9443/cap.wasm",
		HashWXURL:   "https://hash.example.test/hash.wasm",
	}
	current := &cfg
	handler := adminHandlerWithConfigSource(&cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "test-secret", timekeeper.SystemClock{}, func() *config.Config { return current })
	request := func() string {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/login-options", nil))
		return rec.Header().Get("Content-Security-Policy")
	}
	csp := request()
	for _, want := range []string{"'wasm-unsafe-eval'", "https://cap.example.test", "https://wasm.example.test:9443", "https://hash.example.test"} {
		if !strings.Contains(csp, want) {
			t.Errorf("enabled Cap CSP missing %q: %s", want, csp)
		}
	}
	for _, unwanted := range []string{"'unsafe-eval'", "unused-widget.example.test", "https://cap.example.test/site/"} {
		if strings.Contains(csp, unwanted) {
			t.Errorf("enabled Cap CSP contains unnecessary source %q: %s", unwanted, csp)
		}
	}
	updated := cfg
	updated.Console.Login.CAPTCHA.Provider = "builtin"
	current = &updated
	if got := request(); got != adminContentSecurityPolicy() {
		t.Fatalf("live provider change retained Cap permissions: %s", got)
	}
	updated.Console.Login.CAPTCHA.Provider = "cap"
	updated.Console.Login.CAPTCHA.Enabled = false
	if got := request(); got != adminContentSecurityPolicy() {
		t.Fatalf("disabled login CAPTCHA retained Cap permissions: %s", got)
	}
	current = nil
	if got := request(); !strings.Contains(got, "'wasm-unsafe-eval'") {
		t.Fatalf("nil config-source fallback lost the original Cap policy: %s", got)
	}
}
