package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestGuardContextReturnsOnCancellationWhileDetectorIgnoresContext(t *testing.T) {
	baselineSlots := len(guardSlots)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := GuardContext(ctx, func() (*DetectionResult, error) {
			close(started)
			<-release
			close(finished)
			return nil, nil
		})
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("guarded detector did not start")
	}
	cancel()
	startedAt := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("GuardContext error = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
			t.Fatalf("GuardContext returned after cancellation in %s", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("GuardContext waited for detector after context cancellation")
	}

	// The detector is deliberately released after the caller returns. This
	// proves the bounded guard slot remains owned until the abandoned work exits.
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("abandoned detector did not finish after release")
	}
	deadline := time.Now().Add(time.Second)
	for len(guardSlots) > baselineSlots && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(guardSlots); got > baselineSlots {
		t.Fatalf("guard slot leaked after detector exit: baseline=%d current=%d", baselineSlots, got)
	}
}

func TestGuardContextDoesNotLeakWhenLateDetectorPanics(t *testing.T) {
	baselineSlots := len(guardSlots)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := GuardContext(ctx, func() (*DetectionResult, error) {
			<-release
			panic("late detector panic")
		})
		done <- err
	}()
	// Let the guarded goroutine acquire its slot before cancellation.
	deadline := time.Now().Add(time.Second)
	for len(guardSlots) <= baselineSlots && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(guardSlots) <= baselineSlots {
		t.Fatal("guarded detector did not acquire a slot")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("GuardContext error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("GuardContext did not return after cancellation")
	}
	close(release)
	deadline = time.Now().Add(time.Second)
	for len(guardSlots) > baselineSlots && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(guardSlots); got > baselineSlots {
		t.Fatalf("guard slot leaked after late panic: baseline=%d current=%d", baselineSlots, got)
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

func TestBoundedRegexScansBeyondLegacyInputCutoff(t *testing.T) {
	re, err := CompileSafe(`tail-marker`)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Repeat("x", MaxDecodedBytes+32) + "tail-marker"
	matched, err := re.MatchStringStatus(input)
	if err != nil || !matched {
		t.Fatalf("full subject match=(%v,%v), want true,nil", matched, err)
	}
}
