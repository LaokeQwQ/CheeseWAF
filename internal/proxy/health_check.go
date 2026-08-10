package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
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
	key := normalizeUpstream(address)
	if _, ok := r.states[key]; ok {
		r.states[key] = healthy
	}
	r.mu.Unlock()
}

// UpdateSites updates the registry in place so users retain one source of truth.
func (r *HealthRegistry) UpdateSites(sites []config.SiteConfig) {
	if r == nil {
		return
	}
	next := make(map[string]struct{})
	for _, site := range sites {
		for _, upstream := range site.Upstreams {
			next[normalizeUpstream(upstream.Address)] = struct{}{}
		}
	}
	r.mu.Lock()
	for address := range r.states {
		if _, ok := next[address]; !ok {
			delete(r.states, address)
		}
	}
	for address := range next {
		if _, ok := r.states[address]; !ok {
			r.states[address] = true
		}
	}
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
	mu       sync.Mutex
	registry *HealthRegistry
	sites    []config.SiteConfig
	client   *http.Client
	parent   context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
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
	h.mu.Lock()
	h.parent = ctx
	h.restartLocked()
	h.mu.Unlock()
}

// UpdateSites replaces the checker generation after the previous loops exit.
func (h *HealthChecker) UpdateSites(sites []config.SiteConfig) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.sites = append([]config.SiteConfig(nil), sites...)
	if h.parent != nil {
		h.restartLocked()
	}
	h.mu.Unlock()
}

func (h *HealthChecker) restartLocked() {
	if h.cancel != nil {
		h.cancel()
		h.wg.Wait()
	}
	ctx, cancel := context.WithCancel(h.parent)
	h.cancel = cancel
	for _, site := range h.sites {
		if !site.WAF.HealthCheck.Enabled {
			continue
		}
		site := site
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.loop(ctx, site)
		}()
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
		_ = netguard.DrainAndClose(resp.Body)
		h.registry.Set(upstream.Address, resp.StatusCode >= 200 && resp.StatusCode < 500)
	}
}

func normalizeUpstream(address string) string {
	if !strings.Contains(address, "://") {
		return "http://" + address
	}
	return address
}
