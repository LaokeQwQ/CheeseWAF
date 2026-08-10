package semantic

import (
	"regexp"
)

// guardedMatchString keeps a common call site for the bounded-pattern suite.
// Go's regexp engine uses RE2-style linear-time matching, so truncating input is
// neither necessary for backtracking safety nor acceptable in a WAF: an attack
// appended after the truncation point would otherwise bypass inspection.
func guardedMatchString(re *regexp.Regexp, text string, maxInputLen int) bool {
	_ = maxInputLen
	return re.MatchString(text)
}

// guardedMatchString2K retains the existing API while scanning the full bounded
// semantic candidate.
func guardedMatchString2K(re *regexp.Regexp, text string) bool {
	return guardedMatchString(re, text, 2048)
}
