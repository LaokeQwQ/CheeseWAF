// Package engine provides sandboxed execution guards for the detection pipeline.
// All detector invocations are protected against ReDoS, memory exhaustion, and panics.
package engine

import (
	"errors"
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

const (
	// MaxInputBytes is the hard limit on any single input source.
	MaxInputBytes = 512 * 1024 // 512KB
	// MaxDecodedBytes limits post-decompression/decoding expansion.
	MaxDecodedBytes = 2 * 1024 * 1024 // 2MB
	// MaxRegexMatchTime is the deadline for any single regex match.
	MaxRegexMatchTime = 50 * time.Millisecond
	// MaxAllocsPerDetect is the maximum memory allocations per Detect() call.
	MaxAllocsPerDetect = 100_000
	// MaxRegexComplexityScore rejects patterns likely to cause catastrophic backtracking.
	MaxRegexComplexityScore = 30
	// MaxJSONNestingDepth prevents stack overflow from deeply nested JSON.
	MaxJSONNestingDepth = 32
	// MaxMultipartParts prevents excessive multipart form parsing.
	MaxMultipartParts = 64
	// maxInflightRegexMatches bounds timed-out regexp goroutines so ReDoS
	// payloads cannot accumulate unlimited workers (stdlib regexp is not interruptible).
	maxInflightRegexMatches = 64
	// maxInflightGuards bounds detector Guard workers on timeout paths.
	maxInflightGuards = 128
)

// ErrDetectionOverload reports that Guard could not start detector work
// because every bounded worker slot was already occupied.
var ErrDetectionOverload = errors.New("detection overload: too many in-flight guards")

// regexMatchSlots holds a permit until the match goroutine finishes, even after
// the caller timed out. That caps leaked workers under ReDoS load.
var regexMatchSlots = make(chan struct{}, maxInflightRegexMatches)

// guardSlots bounds concurrent Guard workers the same way.
var guardSlots = make(chan struct{}, maxInflightGuards)

// BoundedRegex wraps a regexp.Regexp with timeout protection for ReDoS.
type BoundedRegex struct{ re *regexp.Regexp }

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
	if b == nil || b.re == nil {
		return false
	}
	if len(s) > MaxDecodedBytes {
		s = s[:MaxDecodedBytes]
	}
	select {
	case regexMatchSlots <- struct{}{}:
	default:
		// Overload: fail closed (no-match) rather than spawning more workers.
		return false
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
		return result
	case <-timer.C:
		return false // Treat timeout as no-match to prevent ReDoS
	}
}

// Match performs bounded matching on a byte slice with ReDoS protection.
func (b *BoundedRegex) Match(b2 []byte) bool {
	if b == nil || b.re == nil {
		return false
	}
	if len(b2) > MaxDecodedBytes {
		b2 = b2[:MaxDecodedBytes]
	}
	select {
	case regexMatchSlots <- struct{}{}:
	default:
		return false
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
		return result
	case <-timer.C:
		return false
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

// SanitizeInput bounds and validates raw input before detection.
func SanitizeInput(raw string) string {
	if len(raw) > MaxInputBytes {
		raw = raw[:MaxInputBytes]
	}
	// Strip NULL bytes which can cause issues in some parsers
	raw = strings.ReplaceAll(raw, "\x00", "")
	// Ensure valid UTF-8
	if !utf8.ValidString(raw) {
		raw = strings.ToValidUTF8(raw, "�")
	}
	return raw
}

// DecodeSafe performs bounded decoding that prevents decompression bombs.
func DecodeSafe(raw string) decoder.Decoded {
	safe := SanitizeInput(raw)
	result := decoder.Decode(safe)
	// Prevent decode expansion bombs (e.g., %00%00%00... -> NUL NUL NUL)
	if len(result.Text) > MaxDecodedBytes {
		result.Text = result.Text[:MaxDecodedBytes]
	}
	return result
}

// Guard runs a detection function with panic recovery and timeout protection.
func Guard[T any](fn func() (T, error)) (result T, err error) {
	var zero T
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
				done <- struct {
					res T
					err error
				}{
					err: fmt.Errorf("detector panic recovered: %v\nstack: %s", r, truncate(stack, 500)),
				}
			}
		}()
		res, e := fn()
		done <- struct {
			res T
			err error
		}{res, e}
	}()

	timer := time.NewTimer(2 * time.Second)
	select {
	case r := <-done:
		if !timer.Stop() {
			<-timer.C
		}
		return r.res, r.err
	case <-timer.C:
		return zero, fmt.Errorf("detection deadline exceeded (2s)")
	}
}

// BoundedDecode returns safely decoded text within memory bounds.
func BoundedDecode(raw string) string {
	safe := SanitizeInput(raw)
	result := decoder.Decode(safe)
	if len(result.Text) > MaxDecodedBytes {
		return result.Text[:MaxDecodedBytes]
	}
	return result.Text
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// === Circuit Breaker for Overload Protection ===

type CircuitBreaker struct {
	maxConcurrent int
	current       int32
	mu            sync.Mutex
	open          bool
}

func NewCircuitBreaker(maxConcurrent int) *CircuitBreaker {
	if maxConcurrent <= 0 {
		maxConcurrent = 10000
	}
	return &CircuitBreaker{maxConcurrent: maxConcurrent}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.open {
		return false
	}
	return cb.current < int32(cb.maxConcurrent)
}

// Acquire reserves a slot atomically under the breaker lock (check+increment).
func (cb *CircuitBreaker) Acquire() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.open || cb.current >= int32(cb.maxConcurrent) {
		return false
	}
	cb.current++
	return true
}

func (cb *CircuitBreaker) Release() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.current > 0 {
		cb.current--
	}
}

func (cb *CircuitBreaker) Trip() {
	cb.mu.Lock()
	cb.open = true
	cb.mu.Unlock()
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	cb.open = false
	cb.current = 0
	cb.mu.Unlock()
}

// GlobalCircuitBreaker protects the entire detection pipeline from overload.
var GlobalCircuitBreaker = NewCircuitBreaker(10000)
