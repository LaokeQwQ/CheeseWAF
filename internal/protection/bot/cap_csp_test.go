package bot

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCapChallengeCSPAllowsWASMWithoutJavaScriptEval(t *testing.T) {
	rec := httptest.NewRecorder()
	setCapChallengeDocumentSecurityHeaders(rec, "test-nonce", "https://widget.example.test/cap.js", "https://api.example.test/site/", "https://wasm.example.test/cap.wasm", "https://wasm.example.test/hash.wasm")
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"'nonce-test-nonce' 'wasm-unsafe-eval'", "https://widget.example.test", "connect-src 'self' https://api.example.test https://wasm.example.test", "worker-src blob:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("Cap challenge CSP missing %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		t.Fatalf("Cap challenge enabled general JavaScript eval: %s", csp)
	}
}
