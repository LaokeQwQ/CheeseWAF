package bot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ChallengeBackend is the storage contract behind the bot challenge lifecycle.
//
// Issuing a challenge is a two-phase operation: a node must prove it can pay for
// a slot *before* it spends CPU and entropy generating a puzzle, and it must be
// able to give the slot back when generation fails. A plain "insert a jti" API
// cannot express that, so the transactional methods below exist and MUST be used
// in this order:
//
//	reservation, err := backend.ReserveScoped(ctx, owner, peer, exp) // take capacity
//	if err != nil {
//		return err // nothing reserved, nothing to release
//	}
//	if err = backend.Start(ctx, reservation); err != nil { // generation begins
//		backend.Rollback(ctx, reservation)
//		return err
//	}
//	// ... generate the puzzle, which may still fail ...
//	if err = backend.Commit(ctx, reservation, jti, exp); err != nil { // publish jti
//		backend.Rollback(ctx, reservation)
//		return err
//	}
//
// Callers MUST Rollback on every failure path after a successful ReserveScoped,
// otherwise the reserved capacity (and its rate-limit token) leaks until the
// reservation lease expires. Rollback is idempotent: it reports false when the
// reservation is unknown, already committed, or already released.
//
// Add and Consume are the non-transactional entry points kept for callers that
// manage a jti that was minted elsewhere; they do not participate in capacity
// accounting.
type ChallengeBackend interface {
	// Add stores a jti until exp. Empty owner is allowed.
	Add(ctx context.Context, jti, owner string, exp time.Time) error
	// Consume marks jti used once. Returns false if missing/expired/already used.
	Consume(ctx context.Context, jti string) bool

	// ReserveScoped claims capacity for one challenge owned by owner and rate
	// limited under peer. Either scope may be empty, in which case that scope is
	// not accounted for. The returned reservation holds the capacity until it is
	// committed or rolled back; its lease is bounded and expires on its own.
	// It returns an error (typically ErrChallengeCapacity) when no capacity is
	// left, and never returns a non-nil reservation together with an error.
	ReserveScoped(ctx context.Context, owner, peer string, exp time.Time) (*ChallengeReservation, error)
	// Start marks generation as begun for reservation. It is what makes the
	// issuance rate token irrevocable: after Start a Rollback still releases
	// capacity but no longer refunds the rate window.
	Start(ctx context.Context, r *ChallengeReservation) error
	// Commit publishes jti as a pending challenge until exp and releases the
	// reservation. It fails when the reservation is stale or expired, when jti
	// already exists, or when Start was not called. Callers must Rollback after
	// a failed Commit.
	Commit(ctx context.Context, r *ChallengeReservation, jti string, exp time.Time) error
	// Rollback releases the capacity held by reservation. It reports whether
	// anything was released.
	Rollback(ctx context.Context, r *ChallengeReservation) bool
	// AddScopedWithPeer is the convenience form of the full lifecycle:
	// ReserveScoped -> Start -> Commit, rolling back on any failure.
	AddScopedWithPeer(ctx context.Context, jti, owner, peer string, exp time.Time) error

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

// ReserveScoped forwards to the in-process store, which already owns the
// capacity and rate bookkeeping. ctx is unused: the store is synchronous.
func (m *MemoryBackend) ReserveScoped(_ context.Context, owner, peer string, exp time.Time) (*ChallengeReservation, error) {
	if m == nil || m.store == nil {
		return nil, ErrChallengeCapacity
	}
	return m.store.ReserveScoped(owner, peer, exp)
}

// Start forwards to the in-process store.
func (m *MemoryBackend) Start(_ context.Context, r *ChallengeReservation) error {
	if m == nil || m.store == nil {
		return ErrChallengeCapacity
	}
	return m.store.Start(r)
}

// Commit forwards to the in-process store.
func (m *MemoryBackend) Commit(_ context.Context, r *ChallengeReservation, jti string, exp time.Time) error {
	if m == nil || m.store == nil {
		return ErrChallengeCapacity
	}
	return m.store.Commit(r, jti, exp)
}

// Rollback forwards to the in-process store.
func (m *MemoryBackend) Rollback(_ context.Context, r *ChallengeReservation) bool {
	if m == nil || m.store == nil {
		return false
	}
	return m.store.Rollback(r)
}

// AddScopedWithPeer forwards to the in-process store, which runs the
// ReserveScoped/Start/Commit lifecycle internally.
func (m *MemoryBackend) AddScopedWithPeer(_ context.Context, jti, owner, peer string, exp time.Time) error {
	if m == nil || m.store == nil {
		return ErrChallengeCapacity
	}
	return m.store.AddScopedWithPeer(jti, owner, peer, exp)
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
	//
	// FailOpen only masks *availability* failures (dial/IO/timeout). It never
	// masks *policy* failures: a backend that is reachable and answers "no
	// capacity left" still fails closed.
	FailOpen bool
	// KeyPrefix namespaces Redis keys.
	KeyPrefix string
	// Limits carries the capacity and rate bounds. Only the Redis backend reads
	// it; the memory backend is configured through its own ChallengeStore.
	// Zero values fall back to the defaults NewChallengeStore applies.
	Limits ChallengeStoreConfig
	// ReservationTTL bounds how long an uncommitted reservation keeps its
	// capacity. Defaults to generationReservationTTL.
	ReservationTTL time.Duration
}

// ErrRedisBackendUnavailable reports that Driver=redis was requested but the
// backend could not be brought up (bad URL, unreachable server, failed auth).
// It is never used to refuse a working backend.
var ErrRedisBackendUnavailable = errors.New("bot redis challenge backend is unavailable")

// NewChallengeBackend builds the requested backend. It never silently downgrades
// a requested driver: a failure to reach Redis is returned as an error so the
// operator sees it instead of running on a weaker store.
func NewChallengeBackend(cfg BackendConfig, memory *ChallengeStore) (ChallengeBackend, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Driver)) {
	case "", "memory":
		return NewMemoryBackend(memory), nil
	case "redis":
		backend, err := NewRedisBackend(cfg)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRedisBackendUnavailable, err)
		}
		return backend, nil
	default:
		return nil, fmt.Errorf("unsupported bot challenge backend %q", cfg.Driver)
	}
}
