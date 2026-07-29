package apisec

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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
	start      time.Time
	lastAccess time.Time
	count      int
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
	if l == nil || r == nil {
		return true
	}
	// Apply every matching rule; deny if any rule denies.
	matched := false
	allowAll := true
	for _, rule := range l.rules {
		if rule.cfg.Method != "" && !strings.EqualFold(rule.cfg.Method, r.Method) {
			continue
		}
		if !rule.pattern.MatchString(r.URL.Path) {
			continue
		}
		matched = true
		if !l.allow(rule.cfg, key) {
			allowAll = false
		}
	}
	if !matched {
		return true
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
			l.evictOldestLocked()
		}
		if b == nil && len(l.hits) >= l.maxKeys {
			for k := range l.hits {
				delete(l.hits, k)
				break
			}
		}
		l.hits[mapKey] = &bucket{start: now, lastAccess: now, count: 1}
		return true
	}
	if b.count >= rule.Requests {
		b.lastAccess = now
		return false
	}
	b.count++
	b.lastAccess = now
	return true
}

func (l *RateLimiter) expireLocked(now time.Time) {
	budget := evictionBudget
	for key, b := range l.hits {
		if budget <= 0 {
			break
		}
		budget--
		if now.Sub(b.start) >= time.Hour || now.Sub(b.lastAccess) >= time.Hour {
			delete(l.hits, key)
		}
	}
}

func (l *RateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for key, b := range l.hits {
		if first || b.lastAccess.Before(oldest) {
			oldest = b.lastAccess
			oldestKey = key
			first = false
		}
	}
	if oldestKey != "" {
		delete(l.hits, oldestKey)
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
