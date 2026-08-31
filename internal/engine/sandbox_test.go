package engine

import (
	"errors"
	"strings"
	"testing"
)

func TestGuardSyncRecoversPanicAndReturnsErrors(t *testing.T) {
	if _, err := GuardSync(func() (*DetectionResult, error) {
		panic("boom")
	}); err == nil {
		t.Fatal("GuardSync must recover detector panics")
	}
	want := errors.New("detector failed")
	_, err := GuardSync(func() (*DetectionResult, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("GuardSync error = %v, want %v", err, want)
	}
}

// RegexComplexityScore is a heuristic budget over the pattern text, not a
// backtracking oracle: Go's regexp is RE2-style and cannot blow up
// exponentially, so this gate caps how gnarly a configured pattern may get.
func TestCompileSafeAcceptsOrdinaryPatterns(t *testing.T) {
	for _, pattern := range []string{`(?i)union\s+select`, `AKIA[0-9A-Z]{16}`, `(?i)BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY`} {
		re, err := CompileSafe(pattern)
		if err != nil {
			t.Fatalf("CompileSafe(%q) = %v, want nil", pattern, err)
		}
		if re == nil {
			t.Fatalf("CompileSafe(%q) returned nil regex", pattern)
		}
	}
}

func TestCompileSafeRejectsPatternOverComplexityBudget(t *testing.T) {
	overBudget := strings.Repeat(`[\s\S]*`, MaxRegexComplexityScore/3+1)
	if score := RegexComplexityScore(overBudget); score <= MaxRegexComplexityScore {
		t.Fatalf("fixture score = %d, must exceed budget %d", score, MaxRegexComplexityScore)
	}
	if _, err := CompileSafe(overBudget); err == nil {
		t.Fatal("CompileSafe accepted a pattern over the complexity budget")
	}
	if _, err := CompileSafe(`(`); err == nil {
		t.Fatal("CompileSafe accepted a pattern that does not compile")
	}
}

// BoundedRegex.Regexp is what lets a caller keep CompileSafe's construction
// gate without giving the wrapper control over the match: the stdlib regexp
// scans the whole subject, so a payload past any truncation point is still
// seen. Pin the identity so a future refactor cannot silently swap it out.
func TestBoundedRegexRegexpReturnsUnderlyingStdlibPattern(t *testing.T) {
	re, err := CompileSafe(`(?i)secret`)
	if err != nil {
		t.Fatalf("CompileSafe: %v", err)
	}
	if got := re.Regexp().String(); got != `(?i)secret` {
		t.Fatalf("Regexp().String() = %q", got)
	}
	if !re.Regexp().MatchString("SuperSECRETvalue") {
		t.Fatal("underlying regexp must match")
	}
	var nilBounded *BoundedRegex
	if nilBounded.Regexp() != nil {
		t.Fatal("nil BoundedRegex must expose a nil regexp")
	}
}
