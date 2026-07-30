package bot

import (
	"context"
	"time"
)

// ChallengeBackend is the optional shared challenge/clearance store (R2).
// Default in-process ChallengeStore remains the production path; Redis is opt-in.
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

// NewChallengeBackend builds the configured backend. Unknown drivers fall back to memory.
func NewChallengeBackend(cfg BackendConfig, memory *ChallengeStore) ChallengeBackend {
	switch cfg.Driver {
	case "redis":
		if cfg.RedisURL == "" {
			return NewMemoryBackend(memory)
		}
		rb, err := NewRedisBackend(cfg)
		if err != nil {
			// Construction failure → memory with note via fail-open memory.
			return NewMemoryBackend(memory)
		}
		return rb
	default:
		return NewMemoryBackend(memory)
	}
}
