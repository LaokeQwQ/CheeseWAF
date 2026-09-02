// Package engine provides sandboxed execution guards for the detection pipeline.
// All detector invocations are protected against ReDoS, memory exhaustion, and panics.
package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

const (
	// MaxDecodedBytes limits post-decompression/decoding expansion.
	MaxDecodedBytes = 2 * 1024 * 1024 // 2MB
	// MaxRegexMatchTime is the deadline for any single regex match.
	MaxRegexMatchTime = 50 * time.Millisecond
	// maxAllocsPerDetectCeiling is the intended maximum memory allocations per
	// Detect() call. It is deliberately unexported: nothing enforces it, and an
	// exported name would advertise a capability the engine does not have.
	//
	// It cannot be enforced cheaply: Go has no per-goroutine allocation counter,
	// and runtime.ReadMemStats stop-the-worlds, which is unusable on the request
	// path. The engine bounds allocation structurally instead — per-field size,
	// candidate/node/tree budgets — plus a wall-clock pipeline deadline. Kept
	// only as documentation of the intended ceiling.
	maxAllocsPerDetectCeiling = 100_000
	// MaxRegexComplexityScore rejects patterns likely to cause catastrophic backtracking.
	MaxRegexComplexityScore = 30
	// maxInflightRegexMatches bounds timed-out regexp goroutines so ReDoS
	// payloads cannot accumulate unlimited workers (stdlib regexp is not interruptible).
	maxInflightRegexMatches = 64
	// maxInflightGuards bounds detector Guard workers on timeout paths.
	maxInflightGuards = 128
)

// ErrDetectionOverload reports that Guard could not start detector work
// because every bounded worker slot was already occupied.
var ErrDetectionOverload = errors.New("detection overload: too many in-flight guards")

var (
	// ErrRegexMatchTimeout and ErrRegexMatchOverload let callers that need
	// fail-closed accounting distinguish an incomplete match from a clean
	// negative result. The legacy bool methods retain their compatibility shape.
	ErrRegexMatchTimeout  = errors.New("regular expression match timed out")
	ErrRegexMatchOverload = errors.New("regular expression matcher overloaded")
)

// regexMatchSlots holds a permit until the match goroutine finishes, even after
// the caller timed out. That caps leaked workers under ReDoS load.
var regexMatchSlots = make(chan struct{}, maxInflightRegexMatches)

// guardSlots bounds concurrent Guard workers the same way.
var guardSlots = make(chan struct{}, maxInflightGuards)

// BoundedRegex wraps a regexp.Regexp with timeout protection for ReDoS.
type BoundedRegex struct{ re *regexp.Regexp }

// Regexp returns the compiled stdlib pattern behind the bounded wrapper.
//
// CompileSafe is also a construction-time gate: callers that must keep stdlib
// match semantics (no input truncation, no deadline) use Regexp to run the
// match themselves while still requiring the complexity gate up front. That
// matters for detectors, where silently truncating the subject would let an
// attacker append a payload past the truncation point.
func (b *BoundedRegex) Regexp() *regexp.Regexp {
	if b == nil {
		return nil
	}
	return b.re
}

// CompileSafe compiles a regex pattern and rejects dangerously complex ones.
func CompileSafe(pattern string) (*BoundedRegex, error) {
	if score := RegexComplexityScore(pattern); score > MaxRegexComplexityScore {
		return nil, fmt.Errorf("regex complexity score %d exceeds limit %d: %s", score, MaxRegexComplexityScore, truncate(pattern, 60))
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("regex compile failed: %w", err)
	}
	return &BoundedRegex{re: re}, nil
}

// MatchString performs bounded matching with ReDoS protection via deadline.
func (b *BoundedRegex) MatchString(s string) bool {
	matched, _ := b.MatchStringStatus(s)
	return matched
}

// MatchStringStatus performs the complete match without truncating the
// subject. Go's regexp engine is RE2-based and linear-time; truncation here
// would create a security bypass whenever a payload is appended after the old
// cutoff. Callers that need to surface an incomplete inspection should use the
// returned error.
func (b *BoundedRegex) MatchStringStatus(s string) (bool, error) {
	if b == nil || b.re == nil {
		return false, nil
	}
	select {
	case regexMatchSlots <- struct{}{}:
	default:
		return false, ErrRegexMatchOverload
	}
	done := make(chan bool, 1)
	go func() {
		defer func() { <-regexMatchSlots }()
		done <- b.re.MatchString(s)
	}()
	timer := time.NewTimer(MaxRegexMatchTime)
	select {
	case result := <-done:
		if !timer.Stop() {
			<-timer.C
		}
		return result, nil
	case <-timer.C:
		return false, ErrRegexMatchTimeout
	}
}

// Match performs bounded matching on a byte slice with ReDoS protection.
func (b *BoundedRegex) Match(b2 []byte) bool {
	matched, _ := b.MatchStatus(b2)
	return matched
}

// MatchStatus is the byte-slice counterpart of MatchStringStatus.
func (b *BoundedRegex) MatchStatus(b2 []byte) (bool, error) {
	if b == nil || b.re == nil {
		return false, nil
	}
	select {
	case regexMatchSlots <- struct{}{}:
	default:
		return false, ErrRegexMatchOverload
	}
	done := make(chan bool, 1)
	go func() {
		defer func() { <-regexMatchSlots }()
		done <- b.re.Match(b2)
	}()
	timer := time.NewTimer(MaxRegexMatchTime)
	select {
	case result := <-done:
		if !timer.Stop() {
			<-timer.C
		}
		return result, nil
	case <-timer.C:
		return false, ErrRegexMatchTimeout
	}
}

// RegexComplexityScore estimates the backtracking risk of a regex pattern.
// Higher score = more dangerous. Based on OWASP ReDoS detection heuristics.
func RegexComplexityScore(pattern string) int {
	score := 0
	// Nested quantifiers are the primary ReDoS vector
	for i := 0; i < len(pattern)-2; i++ {
		if isQuantifier(pattern[i+1]) && isQuantifier(pattern[i]) {
			score += 4 // e.g. .*+, .+?, .*?
		}
	}
	// Alternation with overlapping prefixes
	score += strings.Count(pattern, "|") * 1
	// Greedy quantifier on a group that itself contains alternation
	if strings.Contains(pattern, "(.*)") || strings.Contains(pattern, "(.+)") {
		score += 3
	}
	// Long character classes with repetition
	for _, frag := range []string{"[\\s\\S]*", "[\\w\\W]*", "[\\d\\D]*", "[^}]*", ".*?"} {
		score += strings.Count(pattern, frag) * 3
	}
	// Backreferences are expensive
	score += strings.Count(pattern, "\\1") * 5
	score += strings.Count(pattern, "\\2") * 5
	// Lookahead/lookbehind with quantifiers
	if strings.Contains(pattern, "(?=.*)") || strings.Contains(pattern, "(?=.*?)") {
		score += 2
	}
	return score
}

func isQuantifier(b byte) bool {
	return b == '*' || b == '+' || b == '?' || b == '{'
}

// Guard runs a detection function with panic recovery and timeout protection.
// It is the compatibility wrapper for callers without a context; request
// paths should prefer GuardContext so cancellation can end the wait early.
func Guard[T any](fn func() (T, error)) (result T, err error) {
	return GuardContext(context.Background(), fn)
}

// GuardContext runs a detector with panic recovery, a hard upper bound, and
// caller cancellation. The detector runs in a bounded goroutine so a function
// that ignores ctx cannot hold the request path past its budget. When the
// caller returns early, the guard slot remains occupied until the detector
// exits; this preserves the leak bound enforced by guardSlots.
//
// A nil context is treated like context.Background for compatibility with
// callers that do not have a request scope.
func GuardContext[T any](ctx context.Context, fn func() (T, error)) (result T, err error) {
	var zero T
	if ctx == nil {
		ctx = context.Background()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return zero, ctxErr
	}
	select {
	case guardSlots <- struct{}{}:
	default:
		return zero, ErrDetectionOverload
	}
	done := make(chan struct {
		res T
		err error
	}, 1)

	go func() {
		defer func() { <-guardSlots }()
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				out := struct {
					res T
					err error
				}{
					err: fmt.Errorf("detector panic recovered: %v\nstack: %s", r, truncate(stack, 500)),
				}
				// The caller may have returned on ctx.Done. Never let panic
				// reporting block forever on the one-slot result channel.
				select {
				case done <- out:
				default:
				}
			}
		}()
		// Avoid starting detector work when cancellation won the race between
		// admission and goroutine scheduling. A detector that is already running
		// is still allowed to unwind; its slot remains held until it exits.
		if ctxErr := ctx.Err(); ctxErr != nil {
			select {
			case done <- struct {
				res T
				err error
			}{err: ctxErr}:
			default:
			}
			return
		}
		res, e := fn()
		out := struct {
			res T
			err error
		}{res, e}
		select {
		case done <- out:
		default:
		}
	}()

	timer := time.NewTimer(2 * time.Second)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case r := <-done:
		return r.res, r.err
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-timer.C:
		return zero, fmt.Errorf("detection deadline exceeded (2s)")
	}
}

// GuardSync protects a non-blocking detector without creating a goroutine or
// timer. The caller's pipeline context still enforces the request deadline.
func GuardSync[T any](fn func() (T, error)) (result T, err error) {
	var zero T
	select {
	case guardSlots <- struct{}{}:
		defer func() { <-guardSlots }()
	default:
		return zero, ErrDetectionOverload
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("detector panic recovered: %v\nstack: %s", recovered, truncate(string(debug.Stack()), 500))
			result = zero
		}
	}()
	return fn()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
