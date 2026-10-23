package engine

import (
	"strings"
	"testing"
)

// FuzzNormalizeRequestPath checks the security invariants of the path
// normalizer: accepted paths are absolute, contain no NUL or residual
// percent-encoding, and normalize idempotently.
func FuzzNormalizeRequestPath(f *testing.F) {
	for _, seed := range []string{
		"/",
		"/api/foo",
		"/api/../admin",
		"/%2e%2e/%2e%2e/etc/passwd",
		"/..%252fetc%252fpasswd",
		"/api%2Fusers",
		"/foo\x00bar",
		"/%zz",
		"admin",
		".",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, ok := NormalizeRequestPath(raw)
		if !ok {
			return
		}
		if got == "" || !strings.HasPrefix(got, "/") {
			t.Fatalf("accepted path is not absolute: %q -> %q", raw, got)
		}
		if strings.ContainsRune(got, 0) {
			t.Fatalf("accepted path contains NUL: %q -> %q", raw, got)
		}
		if strings.Contains(got, "%") {
			t.Fatalf("accepted path contains residual percent-encoding: %q -> %q", raw, got)
		}
		if got == ".." || strings.HasPrefix(got, "../") || strings.Contains(got, "/../") || strings.HasSuffix(got, "/..") {
			t.Fatalf("accepted path contains traversal: %q -> %q", raw, got)
		}
		again, ok := NormalizeRequestPath(got)
		if !ok || again != got {
			t.Fatalf("normalization is not idempotent: %q -> %q -> (%q, %v)", raw, got, again, ok)
		}
	})
}
