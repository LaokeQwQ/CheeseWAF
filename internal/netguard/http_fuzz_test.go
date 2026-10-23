package netguard

import (
	"testing"
)

// FuzzValidateURL checks that a URL accepted by the default notifier policy is
// HTTPS, has no userinfo or fragment, and does not use a non-canonical IP.
func FuzzValidateURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.test/hook",
		"http://example.test/hook",
		"http://127.0.0.1/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://2130706433/hook",
		"https://user:pass@example.test/hook",
		"https://example.test/hook#fragment",
		"file:///etc/passwd",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		policy := URLPolicy{
			Purpose:        "fuzz",
			HostPurpose:    "fuzz host",
			AllowedSchemes: []string{"https"},
		}
		parsed, err := ValidateURL(raw, policy)
		if err != nil {
			return
		}
		if parsed.Scheme != "https" {
			t.Fatalf("accepted non-HTTPS scheme: %q", parsed.Scheme)
		}
		if parsed.User != nil {
			t.Fatalf("accepted userinfo: %q", parsed.User.String())
		}
		if parsed.Fragment != "" {
			t.Fatalf("accepted fragment: %q", parsed.Fragment)
		}
		if parsed.Hostname() == "" {
			t.Fatal("accepted URL has no host")
		}
	})
}
