// Package ratelimit implements per-key fixed-window request limits.
package ratelimit

import (
	"container/heap"
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

// Limiter is a sharded fixed-window rate limiter with window expiry and a
// hard per-shard key capacity. Full shards deny new keys until a window expires;
// live quotas are never discarded to admit a different client.
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
	mu          sync.Mutex
	keys        map[string]*bucket
	expirations bucketExpiryHeap
}

type bucket struct {
	key         string
	windowStart time.Time
	count       int
	heapIndex   int
}

type bucketExpiryHeap []*bucket

func (h bucketExpiryHeap) Len() int           { return len(h) }
func (h bucketExpiryHeap) Less(i, j int) bool { return h[i].windowStart.Before(h[j].windowStart) }
func (h bucketExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}
func (h *bucketExpiryHeap) Push(value any) {
	b := value.(*bucket)
	b.heapIndex = len(*h)
	*h = append(*h, b)
}
func (h *bucketExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	b := old[last]
	old[last] = nil
	b.heapIndex = -1
	*h = old[:last]
	return b
}

func New(profile config.RateLimitProfile, enabled bool) *Limiter {
	if profile.Requests <= 0 {
		profile.Requests = 100
	}
	if profile.Window <= 0 {
		profile.Window = time.Minute
	}
	// Only default burst when omitted (negative). Explicit 0 stays 0.
	if profile.Burst < 0 {
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
	if l == nil || !l.enabled {
		return true
	}
	if key == "" {
		return false
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
			return false
		}
		if b == nil {
			b = &bucket{key: key, windowStart: now, count: 1}
			sh.keys[key] = b
			heap.Push(&sh.expirations, b)
		} else {
			// Cleanup is bounded, so this expired key may still be indexed.
			// Update its one record instead of retaining stale heap entries.
			b.windowStart, b.count = now, 1
			heap.Fix(&sh.expirations, b.heapIndex)
		}
		return true
	}
	limit := l.requests + l.burst
	if b.count >= limit {
		return false
	}
	b.count++
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
	// Inline FNV-1a (offset 2166136261, prime 16777619) — no heap hash.Hash.
	const (
		fnvOffset = 2166136261
		fnvPrime  = 16777619
	)
	h := uint32(fnvOffset)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= fnvPrime
	}
	return &l.shards[int(h)%len(l.shards)]
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
	// Oldest windows come first, so one due bucket always makes room even
	// when every other key is live. Keep removal work bounded per request.
	for n := 0; n < evictionBudget && len(sh.expirations) > 0; n++ {
		b := sh.expirations[0]
		if now.Sub(b.windowStart) < l.window {
			break
		}
		heap.Pop(&sh.expirations)
		delete(sh.keys, b.key)
	}
}
