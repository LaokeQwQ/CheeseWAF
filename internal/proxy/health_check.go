package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type HealthRegistry struct {
	mu     sync.RWMutex
	states map[string]bool
}

func NewHealthRegistry(sites []config.SiteConfig) *HealthRegistry {
	registry := &HealthRegistry{states: map[string]bool{}}
	for _, site := range sites {
		for _, upstream := range site.Upstreams {
			registry.states[normalizeUpstream(upstream.Address)] = true
		}
	}
	return registry
}

func (r *HealthRegistry) Healthy(address string) bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	healthy, ok := r.states[normalizeUpstream(address)]
	return !ok || healthy
}

func (r *HealthRegistry) Set(address string, healthy bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.states[normalizeUpstream(address)] = healthy
	r.mu.Unlock()
}

func (r *HealthRegistry) Snapshot() map[string]bool {
	out := map[string]bool{}
	if r == nil {
		return out
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for address, healthy := range r.states {
		out[address] = healthy
	}
	return out
}

type HealthChecker struct {
	registry *HealthRegistry
	sites    []config.SiteConfig
	client   *http.Client
}

func NewHealthChecker(sites []config.SiteConfig, registry *HealthRegistry) *HealthChecker {
	return &HealthChecker{
		registry: registry,
		sites:    sites,
		client: &http.Client{
			Timeout:       3 * time.Second,
			CheckRedirect: healthCheckNoRedirect,
		},
	}
}

func healthCheckNoRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (h *HealthChecker) Start(ctx context.Context) {
	if h == nil {
		return
	}
	for _, site := range h.sites {
		if !site.WAF.HealthCheck.Enabled {
			continue
		}
		site := site
		go h.loop(ctx, site)
	}
}

func (h *HealthChecker) loop(ctx context.Context, site config.SiteConfig) {
	interval := site.WAF.HealthCheck.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	h.check(site)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.check(site)
		}
	}
}

func (h *HealthChecker) check(site config.SiteConfig) {
	path := site.WAF.HealthCheck.Path
	if path == "" {
		path = "/"
	}
	timeout := site.WAF.HealthCheck.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := *h.client
	client.Timeout = timeout
	for _, upstream := range site.Upstreams {
		target := normalizeUpstream(upstream.Address)
		u, err := url.Parse(target)
		if err != nil {
			h.registry.Set(upstream.Address, false)
			continue
		}
		u.Path = path
		resp, err := client.Get(u.String())
		if err != nil {
			h.registry.Set(upstream.Address, false)
			continue
		}
		_ = resp.Body.Close()
		h.registry.Set(upstream.Address, resp.StatusCode >= 200 && resp.StatusCode < 500)
	}
}

func normalizeUpstream(address string) string {
	if !strings.Contains(address, "://") {
		return "http://" + address
	}
	return address
}
