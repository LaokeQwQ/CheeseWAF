package captcha

import "testing"

func TestCapResourceOriginAllowsOnlyExactSafeOrigins(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://cap.example.test/site/assets/cap.wasm", "https://cap.example.test"},
		{"https://CAP.example.test:9443/site/", "https://cap.example.test:9443"},
		{"http://127.0.0.1:19384/site/", "http://127.0.0.1:19384"},
		{"http://localhost:19384/site/", "http://localhost:19384"},
		{"http://[::1]:19384/site/", "http://[::1]:19384"},
		{"https://[::ffff:127.0.0.1]:19384/site/", "https://[::ffff:127.0.0.1]:19384"},
		{"https://例子.example/site/", "https://xn--fsqu00a.example"},
		{"https://cap.example.test/site/;script-src%20unsafe-eval", "https://cap.example.test"},
	} {
		if got := CapResourceOrigin(tc.raw); got != tc.want {
			t.Errorf("CapResourceOrigin(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	for _, raw := range []string{
		"", "/assets/cap.wasm", "//cap.example.test/site/", "data:text/plain,hello", "javascript:alert(1)",
		"http://remote.example.test/site/", "https://user:secret@cap.example.test/site/", "https://cap.example.test/?query=1",
		"https://cap.example.test/?", "https://cap.example.test/#fragment", "https://cap.example.test/#", "https://*.example.test/site/",
		"https://cap.example.test:0/site/", "https://cap.example.test:65536/site/", "https://cap.example.test:/site/",
		"https://cap.example.test;unsafe-eval/site/", "https://cap.example.test/\nscript-src 'unsafe-eval'",
	} {
		if got := CapResourceOrigin(raw); got != "" {
			t.Errorf("invalid resource URL %q became CSP source %q", raw, got)
		}
	}
}
