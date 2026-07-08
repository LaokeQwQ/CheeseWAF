package blockpage

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewTraceIDFallbackRemainsUniqueWhenRandomUnavailable(t *testing.T) {
	previousReader := readTraceRandom
	readTraceRandom = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	defer func() { readTraceRandom = previousReader }()
	atomic.StoreUint64(&traceFallbackCounter, 0)

	first := NewTraceID()
	second := NewTraceID()
	if !strings.HasPrefix(first, "cw-") || !strings.HasPrefix(second, "cw-") {
		t.Fatalf("expected cw trace IDs, got %q and %q", first, second)
	}
	if first == second {
		t.Fatalf("expected unique fallback trace IDs, got %q", first)
	}
}
