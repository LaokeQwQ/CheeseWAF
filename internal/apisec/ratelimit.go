package apisec

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

const (
	defaultMaxKeys = 50_000
	evictionBudget = 8
)

type RateLimiter struct {
	rules   []limitRule
	now     func() time.Time
	mu      sync.Mutex
	hits    map[string]*bucket
	maxKeys int
}

type limitRule struct {
	cfg         config.APIEndpointLimitConfig
	pattern     *regexp.Regexp
	specificity int
}

type bucket struct {
	start     time.Time
	expiresAt time.Time
	count     int
}

func NewRateLimiter(cfg []config.APIEndpointLimitConfig) (*RateLimiter, error) {
	limiter := &RateLimiter{now: time.Now, hits: map[string]*bucket{}, maxKeys: defaultMaxKeys}
	for _, item := range cfg {
		if !item.Enabled {
			continue
		}
		pattern, err := regexp.Compile(item.PathPattern)
		if err != nil {
			return nil, err
		}
		limiter.rules = append(limiter.rules, limitRule{
			cfg:         item,
			pattern:     pattern,
			specificity: len(item.PathPattern),
		})
	}
	// Prefer more specific path patterns first.
	for i := 0; i < len(limiter.rules); i++ {
		for j := i + 1; j < len(limiter.rules); j++ {
			if limiter.rules[j].specificity > limiter.rules[i].specificity {
				limiter.rules[i], limiter.rules[j] = limiter.rules[j], limiter.rules[i]
			}
		}
	}
	return limiter, nil
}

func (l *RateLimiter) Allow(r *http.Request, key string) bool {
	return l.AllowRequests([]*http.Request{r}, key)
}

// AllowRequests checks the public and upstream identities of one request. A
// matching rule consumes its budget once even when several identities match it.
func (l *RateLimiter) AllowRequests(requests []*http.Request, key string) bool {
	if l == nil {
		return true
	}
	requestPaths := make([][]string, len(requests))
	for i, r := range requests {
		if r == nil {
			continue
		}
		if r.URL == nil {
			return false
		}
		paths, valid := engine.SecurityPathViews(r.URL.Path)
		if !valid {
			return false
		}
		requestPaths[i] = paths
	}
	// Apply every matching rule; deny if any rule denies.
	allowAll := true
	for _, rule := range l.rules {
		for i, r := range requests {
			if r == nil || (rule.cfg.Method != "" && !strings.EqualFold(rule.cfg.Method, r.Method)) {
				continue
			}
			if !matchesEndpointPath(rule.pattern, requestPaths[i]) {
				continue
			}
			if !l.allow(rule.cfg, key) {
				allowAll = false
			}
			break
		}
	}
	return allowAll
}

func (l *RateLimiter) allow(rule config.APIEndpointLimitConfig, key string) bool {
	if key == "" {
		key = "anonymous"
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked(now)
	mapKey := rule.ID + "|" + key
	b := l.hits[mapKey]
	if b == nil || now.Sub(b.start) >= rule.Window {
		if b == nil && len(l.hits) >= l.maxKeys {
			// An active quota must outlive capacity pressure from new identities.
			return false
		}
		l.hits[mapKey] = &bucket{start: now, expiresAt: now.Add(rule.Window), count: 1}
		return true
	}
	if b.count >= rule.Requests {
		return false
	}
	b.count++
	return true
}

func (l *RateLimiter) expireLocked(now time.Time) {
	// Keep cleanup bounded even at capacity. Different endpoint rules can have
	// different windows; a shared idle TTL must not reset a still-live quota.
	budget := evictionBudget
	for key, b := range l.hits {
		if budget <= 0 {
			break
		}
		budget--
		if !now.Before(b.expiresAt) {
			delete(l.hits, key)
		}
	}
}

// KeyCount returns live keys (tests/ops).
func (l *RateLimiter) KeyCount() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}
