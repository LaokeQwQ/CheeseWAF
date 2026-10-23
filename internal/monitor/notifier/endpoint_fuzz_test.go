package notifier

import (
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// FuzzWebhookEndpoint checks the notifier endpoint gate: when credentials are
// configured the endpoint must be HTTPS, and invalid URLs must not panic.
func FuzzWebhookEndpoint(f *testing.F) {
	for _, seed := range []string{
		"https://example.test/hook",
		"http://example.test/hook",
		"ftp://example.test/hook",
		"https://user:pass@example.test/hook",
		"://bad",
		"",
		"https://[::1]/hook",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, endpoint string) {
		if len(endpoint) > 8192 {
			t.Skip()
		}
		cfg := config.NotifierConfig{ID: "fuzz", Endpoint: endpoint, Token: "secret"}
		parsed, err := validateWebhookEndpoint(cfg)
		if err != nil {
			return
		}
		if parsed == nil {
			t.Fatal("nil URL without error")
		}
		if !strings.EqualFold(parsed.Scheme, "https") {
			t.Fatalf("credentialed endpoint accepted non-HTTPS scheme %q", parsed.Scheme)
		}
	})
}
