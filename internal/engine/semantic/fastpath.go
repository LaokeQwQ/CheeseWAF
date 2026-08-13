// Package semantic implements fast paths for string operations in security detectors.
// These are compiler-friendly patterns that allow inlining and auto-vectorization.
package semantic

import "strings"

// containsAny returns true if text contains any of the needles.
// This is a hot path in SQL/XSS/RCE detection. The loop allows the compiler
// to auto-vectorize on platforms with SSE4.2/AVX2 (amd64) or NEON (arm64).
//
//go:inline
func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

// containsAll returns true if text contains all needles.
//
//go:inline
func containsAll(text string, needles []string) bool {
	for _, needle := range needles {
		if !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}

// hasPrefix returns true if text has any of the prefixes.
//
//go:inline
func hasPrefix(text string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// hasSuffix returns true if text has any of the suffixes.
//
//go:inline
func hasSuffix(text string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(text, suffix) {
			return true
		}
	}
	return false
}

// SQL injection detection common needles (for containsAny)
var sqlCommonNeedles = []string{
	"'", ";", "--", "/*",
	" select ", " exec ", " execute ", " begin ", " declare ",
}

// SQL injection compact patterns (no spaces, lowercase)
var sqlCompactNeedles = []string{
	"unionselect", "or1=1",
}
