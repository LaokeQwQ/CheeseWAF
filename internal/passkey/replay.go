package passkey

import (
	"sync"
	"time"
)

const defaultReplayCapacity = 100_000

// ReplayGuard atomically records consumed challenge token IDs. Implementations
// shared across processes or restarts must provide the same single-use
// guarantee; MemoryReplayGuard alone does not survive a process restart.
type ReplayGuard interface {
	// Consume reports whether the token was newly recorded. It returns false
	// when the token ID has already been consumed and is still unexpired.
	Consume(tokenID [16]byte, now, expiresAt time.Time) (bool, error)
}

// MemoryReplayGuard is a bounded, concurrency-safe in-process ReplayGuard.
// Expired token IDs are pruned when capacity is reached.
type MemoryReplayGuard struct {
	mu       sync.Mutex
	seen     map[[16]byte]time.Time
	capacity int
}

// NewMemoryReplayGuard creates a guard with the supplied capacity. A
// non-positive capacity selects the default bound.
func NewMemoryReplayGuard(capacity int) *MemoryReplayGuard {
	if capacity <= 0 {
		capacity = defaultReplayCapacity
	}

	return &MemoryReplayGuard{
		seen:     make(map[[16]byte]time.Time, min(capacity, 1024)),
		capacity: capacity,
	}
}

// Consume implements ReplayGuard.
func (g *MemoryReplayGuard) Consume(tokenID [16]byte, now, expiresAt time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if seenAt, ok := g.seen[tokenID]; ok {
		if seenAt.After(now) {
			return false, nil
		}

		delete(g.seen, tokenID)
	}

	if len(g.seen) >= g.capacity {
		for id, at := range g.seen {
			if !at.After(now) {
				delete(g.seen, id)
			}
		}

		if len(g.seen) >= g.capacity {
			return false, ErrReplayGuardFull
		}
	}

	g.seen[tokenID] = expiresAt

	return true, nil
}
