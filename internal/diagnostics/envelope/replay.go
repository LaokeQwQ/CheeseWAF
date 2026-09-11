package envelope

import (
	"context"
	"fmt"
	"sync"
)

// MemoryReplayGuard is a bounded, process-local replay barrier for one-shot
// diagnostic consumption. It fails closed when full instead of evicting old
// identities and silently reopening a replay window.
type MemoryReplayGuard struct {
	mu      sync.Mutex
	max     int
	seen    map[string]struct{}
	pending map[string]struct{}
	closed  bool
}

// NewMemoryReplayGuard creates a bounded in-memory guard. A non-positive bound
// selects a conservative default rather than an unbounded map.
func NewMemoryReplayGuard(maxEntries int) *MemoryReplayGuard {
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	return &MemoryReplayGuard{max: maxEntries, seen: make(map[string]struct{}, maxEntries), pending: make(map[string]struct{}, maxEntries)}
}

func (g *MemoryReplayGuard) validate(ctx context.Context, id string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if g == nil {
		return ErrReplayGuardUnavailable
	}
	if err := validateBoundedText("envelope id", id, MaxEnvelopeIDBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	return nil
}

// Reserve atomically reserves id. A second reservation returns ErrReplay.
func (g *MemoryReplayGuard) Reserve(ctx context.Context, id string) error {
	if err := g.validate(ctx, id); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrReplayGuardUnavailable
	}
	if _, exists := g.seen[id]; exists {
		return ErrReplay
	}
	if _, exists := g.pending[id]; exists {
		return ErrReplay
	}
	if len(g.seen)+len(g.pending) >= g.max {
		return ErrReplayGuardFull
	}
	g.pending[id] = struct{}{}
	return nil
}

// Commit makes a prior reservation permanent. It is idempotent for an already
// committed identity so a successful upload is never retried because of a
// duplicate completion notification.
func (g *MemoryReplayGuard) Commit(ctx context.Context, id string) error {
	if err := g.validate(ctx, id); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrReplayGuardUnavailable
	}
	if _, exists := g.seen[id]; exists {
		return nil
	}
	if _, exists := g.pending[id]; !exists {
		return ErrReplayReservation
	}
	delete(g.pending, id)
	g.seen[id] = struct{}{}
	return nil
}

// Release removes a pending reservation so a failed upload can be retried.
// Releasing an already committed identity is a no-op.
func (g *MemoryReplayGuard) Release(ctx context.Context, id string) error {
	if err := g.validate(ctx, id); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrReplayGuardUnavailable
	}
	delete(g.pending, id)
	return nil
}

// CheckAndMark retains the legacy one-shot behavior for callers that do not
// need a reservation lifecycle.
func (g *MemoryReplayGuard) CheckAndMark(ctx context.Context, id string) error {
	if err := g.Reserve(ctx, id); err != nil {
		return err
	}
	if err := g.Commit(ctx, id); err != nil {
		_ = g.Release(context.Background(), id)
		return err
	}
	return nil
}

// Mark and Consume are compatibility spellings for CheckAndMark.
func (g *MemoryReplayGuard) Mark(ctx context.Context, id string) error {
	return g.CheckAndMark(ctx, id)
}

func (g *MemoryReplayGuard) Consume(ctx context.Context, id string) error {
	return g.CheckAndMark(ctx, id)
}

// Seen reports whether id is pending or has already been committed. It is
// intended for diagnostics and tests; it does not reserve an identity.
func (g *MemoryReplayGuard) Seen(id string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.seen[id]; ok {
		return true
	}
	_, ok := g.pending[id]
	return ok
}

// Len returns the number of reserved identities.
func (g *MemoryReplayGuard) Len() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}

// Close prevents further reservations and releases the identity map.
func (g *MemoryReplayGuard) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	for id := range g.seen {
		delete(g.seen, id)
	}
	for id := range g.pending {
		delete(g.pending, id)
	}
	g.closed = true
	return nil
}
