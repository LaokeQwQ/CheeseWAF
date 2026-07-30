package engine

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompileSafeRejectsHighComplexity(t *testing.T) {
	// Nested quantifiers (+4 each pair) and many backrefs push past MaxRegexComplexityScore.
	pattern := `(a+)+(b+)+` + strings.Repeat(`\1\2`, 8)
	if score := RegexComplexityScore(pattern); score <= MaxRegexComplexityScore {
		t.Fatalf("test pattern score %d not above limit %d", score, MaxRegexComplexityScore)
	}
	if _, err := CompileSafe(pattern); err == nil {
		t.Fatal("expected high-complexity pattern to be rejected")
	}
}

func TestBoundedRegexMatchStringSimple(t *testing.T) {
	re, err := CompileSafe(`hello`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !re.MatchString("say hello world") {
		t.Fatal("expected match")
	}
	if re.MatchString("nope") {
		t.Fatal("expected no match")
	}
}

func TestCircuitBreakerAcquireReleaseAtomic(t *testing.T) {
	cb := NewCircuitBreaker(2)
	if !cb.Acquire() || !cb.Acquire() {
		t.Fatal("expected first two acquires to succeed")
	}
	if cb.Acquire() {
		t.Fatal("expected third acquire to fail at capacity")
	}
	cb.Release()
	if !cb.Acquire() {
		t.Fatal("expected acquire after release")
	}
}

func TestCircuitBreakerConcurrentAcquireBounded(t *testing.T) {
	cb := NewCircuitBreaker(8)
	var wg sync.WaitGroup
	var ok int
	var mu sync.Mutex
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cb.Acquire() {
				mu.Lock()
				ok++
				mu.Unlock()
				time.Sleep(time.Millisecond)
				cb.Release()
			}
		}()
	}
	wg.Wait()
	if ok < 8 {
		t.Fatalf("expected at least capacity successful acquires, got %d", ok)
	}
	// After all releases, capacity should be free again.
	if !cb.Acquire() {
		t.Fatal("expected acquire after concurrent drain")
	}
	cb.Release()
}
