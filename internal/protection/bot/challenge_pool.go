package bot

import (
	"errors"
	"sync"
)

// ErrChallengeBusy is returned when concurrent challenge generation is saturated.
// Callers should map this to HTTP 503.
var ErrChallengeBusy = errors.New("challenge worker pool is busy")

// ChallengeWorkerPool bounds concurrent challenge generation (CPU/crypto work).
// Capacity and rate limits still live in ChallengeStore; this pool is the
// execution gate so overload fails closed with 503 instead of unbounded work.
type ChallengeWorkerPool struct {
	sem chan struct{}
}

// NewChallengeWorkerPool creates a pool with the given concurrency.
// Values below 1 default to 64.
func NewChallengeWorkerPool(concurrency int) *ChallengeWorkerPool {
	if concurrency < 1 {
		concurrency = 64
	}
	return &ChallengeWorkerPool{sem: make(chan struct{}, concurrency)}
}

// TryRun runs fn if a worker slot is free. Returns ErrChallengeBusy otherwise.
func (p *ChallengeWorkerPool) TryRun(fn func() error) error {
	if p == nil || p.sem == nil {
		if fn == nil {
			return nil
		}
		return fn()
	}
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
		if fn == nil {
			return nil
		}
		return fn()
	default:
		return ErrChallengeBusy
	}
}

// Cap returns the pool size.
func (p *ChallengeWorkerPool) Cap() int {
	if p == nil || p.sem == nil {
		return 0
	}
	return cap(p.sem)
}

// InUse returns approximate in-flight workers.
func (p *ChallengeWorkerPool) InUse() int {
	if p == nil || p.sem == nil {
		return 0
	}
	return len(p.sem)
}

// Shared pool wiring for Policy (avoids nil checks scattering).
type poolHolder struct {
	once sync.Once
	pool *ChallengeWorkerPool
}

func (h *poolHolder) get(concurrency int) *ChallengeWorkerPool {
	h.once.Do(func() {
		h.pool = NewChallengeWorkerPool(concurrency)
	})
	return h.pool
}
