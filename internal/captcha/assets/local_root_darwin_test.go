//go:build darwin

package assets

import "testing"

func TestNormalizeSecureRootPathAcceptsMacOSSystemAliases(t *testing.T) {
	tests := map[string]string{
		"/var/folders/example": "/private/var/folders/example",
		"/tmp/example":         "/private/tmp/example",
		"/etc/cheesewaf":       "/private/etc/cheesewaf",
		"/Users/example":       "/Users/example",
		"/variable/example":    "/variable/example",
	}
	for input, expected := range tests {
		if actual := normalizeSecureRootPath(input); actual != expected {
			t.Errorf("normalizeSecureRootPath(%q) = %q, want %q", input, actual, expected)
		}
	}
}
