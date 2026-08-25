package bot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ChallengeBackend is an internal extension point for a future shared
// challenge store. Policy currently uses its in-process stores directly.
type ChallengeBackend interface {
	// Add stores a jti until exp. Empty owner is allowed.
	Add(ctx context.Context, jti, owner string, exp time.Time) error
	// Consume marks jti used once. Returns false if missing/expired/already used.
	Consume(ctx context.Context, jti string) bool
	// Close releases backend resources.
	Close() error
}

// MemoryBackend adapts ChallengeStore to ChallengeBackend.
type MemoryBackend struct {
	store *ChallengeStore
}

// NewMemoryBackend wraps an existing ChallengeStore.
func NewMemoryBackend(store *ChallengeStore) *MemoryBackend {
	if store == nil {
		store = NewChallengeStore(ChallengeStoreConfig{})
	}
	return &MemoryBackend{store: store}
}

func (m *MemoryBackend) Add(_ context.Context, jti, owner string, exp time.Time) error {
	if m == nil || m.store == nil {
		return ErrChallengeCapacity
	}
	return m.store.AddScoped(jti, owner, exp)
}

func (m *MemoryBackend) Consume(_ context.Context, jti string) bool {
	if m == nil || m.store == nil {
		return false
	}
	_, ok := m.store.Consume(jti)
	return ok
}

func (m *MemoryBackend) Close() error { return nil }

// BackendConfig selects the challenge store implementation.
type BackendConfig struct {
	// Driver is "memory" (default) or "redis".
	Driver string
	// RedisURL e.g. redis://127.0.0.1:6379/0 — only used when Driver=redis.
	RedisURL string
	// FailOpen when true allows traffic if Redis is down (weaker multi-node guarantee).
	// Default false = fail closed for consume/add when Redis unavailable.
	FailOpen bool
	// KeyPrefix namespaces Redis keys.
	KeyPrefix string
}

var ErrRedisBackendUnavailable = errors.New("bot Redis challenge backend is not wired into Policy")

// NewChallengeBackend never silently downgrades a requested backend. It is
// retained for future wiring, but Redis must not appear active while Policy is
// still using its in-process challenge lifecycle.
func NewChallengeBackend(cfg BackendConfig, memory *ChallengeStore) (ChallengeBackend, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Driver)) {
	case "", "memory":
		return NewMemoryBackend(memory), nil
	case "redis":
		return nil, fmt.Errorf("%w: use memory", ErrRedisBackendUnavailable)
	default:
		return nil, fmt.Errorf("unsupported bot challenge backend %q", cfg.Driver)
	}
}
