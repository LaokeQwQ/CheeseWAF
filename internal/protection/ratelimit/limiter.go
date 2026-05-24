// Package ratelimit implements per-key sliding window request limits.
package ratelimit

import (
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Limiter struct {
	mu       sync.Mutex
	enabled  bool
	requests int
	window   time.Duration
	burst    int
	keys     map[string]*bucket
	now      func() time.Time
}

type bucket struct {
	windowStart time.Time
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
	return &Limiter{
		enabled:  enabled,
		requests: profile.Requests,
		window:   profile.Window,
		burst:    profile.Burst,
		keys:     map[string]*bucket{},
		now:      time.Now,
	}
}

func (l *Limiter) Allow(key string) bool {
	if l == nil || !l.enabled || key == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.keys[key]
	if b == nil || now.Sub(b.windowStart) >= l.window {
		l.keys[key] = &bucket{windowStart: now, count: 1}
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
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.keys {
		out[key] = b.count
	}
	return out
}
