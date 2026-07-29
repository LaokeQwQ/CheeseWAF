// Package ratelimit implements per-key sliding window request limits.
package ratelimit

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	defaultShards = 32
	// Global soft cap; each shard enforces maxKeys/shards (min 64).
	defaultMaxKeys = 100_000
	// Bound work under a single shard lock (expired key cleanup).
	evictionBudget = 8
)

// Limiter is a sharded sliding-window rate limiter with window expiry and a
// hard per-shard key capacity (oldest last-access keys are dropped when full).
type Limiter struct {
	enabled  bool
	requests int
	window   time.Duration
	burst    int
	maxKeys  int
	shards   []limiterShard
	now      func() time.Time
}

type limiterShard struct {
	mu   sync.Mutex
	keys map[string]*bucket
}

type bucket struct {
	windowStart time.Time
	lastAccess  time.Time
	count       int
}

func New(profile config.RateLimitProfile, enabled bool) *Limiter {
	if profile.Requests <= 0 {
		profile.Requests = 100
	}
	if profile.Window <= 0 {
		profile.Window = time.Minute
	}
	if profile.Burst <= 0 {
		profile.Burst = profile.Requests
	}
	shards := make([]limiterShard, defaultShards)
	for i := range shards {
		shards[i].keys = map[string]*bucket{}
	}
	return &Limiter{
		enabled:  enabled,
		requests: profile.Requests,
		window:   profile.Window,
		burst:    profile.Burst,
		maxKeys:  defaultMaxKeys,
		shards:   shards,
		now:      time.Now,
	}
}

// WithMaxKeys overrides the global key capacity (tests).
func (l *Limiter) WithMaxKeys(n int) *Limiter {
	if l != nil && n > 0 {
		l.maxKeys = n
	}
	return l
}

func (l *Limiter) Allow(key string) bool {
	if l == nil || !l.enabled || key == "" {
		return true
	}
	now := l.now()
	sh := l.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	l.expireLocked(sh, now)
	capPer := l.perShardCap()
	b := sh.keys[key]
	if b == nil || now.Sub(b.windowStart) >= l.window {
		if b == nil && len(sh.keys) >= capPer {
			l.evictOldestLocked(sh, now)
		}
		// After eviction still full: replace one entry (prefer allow path).
		if b == nil && len(sh.keys) >= capPer {
			for k := range sh.keys {
				delete(sh.keys, k)
				break
			}
		}
		sh.keys[key] = &bucket{windowStart: now, lastAccess: now, count: 1}
		return true
	}
	limit := l.requests + l.burst
	if b.count >= limit {
		b.lastAccess = now
		return false
	}
	b.count++
	b.lastAccess = now
	return true
}

func (l *Limiter) Snapshot() map[string]int {
	out := map[string]int{}
	if l == nil {
		return out
	}
	now := l.now()
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		l.expireLocked(sh, now)
		for key, b := range sh.keys {
			out[key] = b.count
		}
		sh.mu.Unlock()
	}
	return out
}

// KeyCount returns live keys across shards (for tests/ops).
func (l *Limiter) KeyCount() int {
	if l == nil {
		return 0
	}
	total := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		total += len(sh.keys)
		sh.mu.Unlock()
	}
	return total
}

func (l *Limiter) shard(key string) *limiterShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &l.shards[int(h.Sum32())%len(l.shards)]
}

func (l *Limiter) perShardCap() int {
	n := len(l.shards)
	if n < 1 {
		n = 1
	}
	capPer := l.maxKeys / n
	if capPer < 64 {
		capPer = 64
	}
	return capPer
}

func (l *Limiter) expireLocked(sh *limiterShard, now time.Time) {
	budget := evictionBudget
	for key, b := range sh.keys {
		if budget <= 0 {
			break
		}
		if now.Sub(b.windowStart) >= l.window {
			delete(sh.keys, key)
			budget--
		}
	}
}

func (l *Limiter) evictOldestLocked(sh *limiterShard, now time.Time) {
	l.expireLocked(sh, now)
	if len(sh.keys) < l.perShardCap() {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for key, b := range sh.keys {
		if first || b.lastAccess.Before(oldest) {
			oldest = b.lastAccess
			oldestKey = key
			first = false
		}
	}
	if oldestKey != "" {
		delete(sh.keys, oldestKey)
	}
}
