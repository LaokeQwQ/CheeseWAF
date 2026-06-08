package apisec

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type RateLimiter struct {
	rules []limitRule
	now   func() time.Time
	mu    sync.Mutex
	hits  map[string]*bucket
}

type limitRule struct {
	cfg     config.APIEndpointLimitConfig
	pattern *regexp.Regexp
}

type bucket struct {
	start time.Time
	count int
}

func NewRateLimiter(cfg []config.APIEndpointLimitConfig) (*RateLimiter, error) {
	limiter := &RateLimiter{now: time.Now, hits: map[string]*bucket{}}
	for _, item := range cfg {
		if !item.Enabled {
			continue
		}
		pattern, err := regexp.Compile(item.PathPattern)
		if err != nil {
			return nil, err
		}
		limiter.rules = append(limiter.rules, limitRule{cfg: item, pattern: pattern})
	}
	return limiter, nil
}

func (l *RateLimiter) Allow(r *http.Request, key string) bool {
	if l == nil || r == nil {
		return true
	}
	for _, rule := range l.rules {
		if rule.cfg.Method != "" && !strings.EqualFold(rule.cfg.Method, r.Method) {
			continue
		}
		if !rule.pattern.MatchString(r.URL.Path) {
			continue
		}
		return l.allow(rule.cfg, key)
	}
	return true
}

func (l *RateLimiter) allow(rule config.APIEndpointLimitConfig, key string) bool {
	if key == "" {
		key = "anonymous"
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.hits[rule.ID+"|"+key]
	if b == nil || now.Sub(b.start) >= rule.Window {
		l.hits[rule.ID+"|"+key] = &bucket{start: now, count: 1}
		return true
	}
	if b.count >= rule.Requests {
		return false
	}
	b.count++
	return true
}
