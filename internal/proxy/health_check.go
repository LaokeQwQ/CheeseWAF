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
	states map[string]upstreamHealthState
}

type upstreamHealthState struct {
	healthy            bool
	consecutiveSuccess int
	consecutiveFailure int
	healthyThreshold   int
	unhealthyThreshold int
}

func NewHealthRegistry(sites []config.SiteConfig) *HealthRegistry {
	registry := &HealthRegistry{states: map[string]upstreamHealthState{}}
	for _, site := range sites {
		for _, upstream := range site.Upstreams {
			registry.addUpstream(upstream.Address, site.WAF.HealthCheck)
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
	state, ok := r.states[normalizeUpstream(address)]
	return !ok || state.healthy
}

func (r *HealthRegistry) Set(address string, healthy bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	key := normalizeUpstream(address)
	if state, ok := r.states[key]; ok {
		if healthy {
			state.consecutiveFailure = 0
			state.consecutiveSuccess++
			if state.consecutiveSuccess >= state.healthyThreshold {
				state.healthy = true
			}
		} else {
			state.consecutiveSuccess = 0
			state.consecutiveFailure++
			if state.consecutiveFailure >= state.unhealthyThreshold {
				state.healthy = false
			}
		}
		r.states[key] = state
	}
	r.mu.Unlock()
}

// UpdateSites updates the registry in place so users retain one source of truth.
func (r *HealthRegistry) UpdateSites(sites []config.SiteConfig) {
	if r == nil {
		return
	}
	next := NewHealthRegistry(sites).states
	for _, site := range sites {
		_ = site
	}
	r.mu.Lock()
	for address := range r.states {
		if _, ok := next[address]; !ok {
			delete(r.states, address)
		}
	}
	for address, configured := range next {
		if current, ok := r.states[address]; ok {
			current.healthyThreshold = configured.healthyThreshold
			current.unhealthyThreshold = configured.unhealthyThreshold
			r.states[address] = current
		} else {
			r.states[address] = configured
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
	for address, state := range r.states {
		out[address] = state.healthy
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
		h.registry.Set(upstream.Address, resp.StatusCode >= 200 && resp.StatusCode < 400)
	}
}

func (r *HealthRegistry) addUpstream(address string, cfg config.HealthCheckConfig) {
	key := normalizeUpstream(address)
	healthyThreshold := cfg.HealthyThreshold
	if healthyThreshold <= 0 {
		healthyThreshold = 1
	}
	unhealthyThreshold := cfg.UnhealthyThreshold
	if unhealthyThreshold <= 0 {
		unhealthyThreshold = 1
	}
	if existing, ok := r.states[key]; ok {
		if healthyThreshold > existing.healthyThreshold {
			existing.healthyThreshold = healthyThreshold
		}
		if unhealthyThreshold > existing.unhealthyThreshold {
			existing.unhealthyThreshold = unhealthyThreshold
		}
		r.states[key] = existing
		return
	}
	r.states[key] = upstreamHealthState{
		healthy:            true,
		healthyThreshold:   healthyThreshold,
		unhealthyThreshold: unhealthyThreshold,
	}
}

func normalizeUpstream(address string) string {
	if !strings.Contains(address, "://") {
		return "http://" + address
	}
	return address
}
