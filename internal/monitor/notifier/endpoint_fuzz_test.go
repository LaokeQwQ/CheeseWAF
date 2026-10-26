package notifier

import (
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// FuzzCredentialedEndpoints checks the notifier endpoint gate: a provider that
// carries a credential must reject a non-HTTPS endpoint, and malformed URLs
// must not panic.
func FuzzCredentialedEndpoints(f *testing.F) {
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

	builders := map[string]func(config.NotifierConfig) (string, error){
		"dingtalk":    dingTalkEndpoint,
		"telegram":    telegramEndpoint,
		"datadog":     datadogEventsEndpoint,
		"grafana":     grafanaAnnotationsEndpoint,
		"flashcat":    flashcatEventEndpoint,
		"nightingale": nightingaleCallbackEndpoint,
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		if len(endpoint) > 8192 {
			t.Skip()
		}
		cfg := config.NotifierConfig{ID: "fuzz", Endpoint: endpoint, Token: "secret"}
		for name, build := range builders {
			built, err := build(cfg)
			if err != nil {
				continue
			}
			parsed, err := url.Parse(built)
			if err != nil {
				t.Fatalf("%s returned unparsable endpoint %q: %v", name, built, err)
			}
			if !strings.EqualFold(parsed.Scheme, "https") {
				t.Fatalf("%s accepted non-HTTPS scheme %q", name, parsed.Scheme)
			}
		}
	})
}
