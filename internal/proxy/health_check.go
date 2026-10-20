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
			registry.addUpstream(siteHealthKey(site.ID, upstream.Address), site.WAF.HealthCheck)
		}
	}
	return registry
}

func siteHealthKey(siteID, address string) string {
	return siteID + "\x00" + normalizeUpstream(address)
}
func (r *HealthRegistry) Healthy(address string) bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for key, state := range r.states {
		if key == normalizeUpstream(address) || strings.HasSuffix(key, "\x00"+normalizeUpstream(address)) {
			if !state.healthy {
				return false
			}
		}
	}
	return true
}
func (r *HealthRegistry) HealthyForSite(siteID, address string) bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	state, ok := r.states[siteHealthKey(siteID, address)]
	return !ok || state.healthy
}
func updateHealth(state upstreamHealthState, healthy bool) upstreamHealthState {
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
	return state
}
func (r *HealthRegistry) SetForSite(siteID, address string, healthy bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := siteHealthKey(siteID, address)
	if state, ok := r.states[key]; ok {
		r.states[key] = updateHealth(state, healthy)
	}
}
func (r *HealthRegistry) Set(address string, healthy bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, state := range r.states {
		if key == normalizeUpstream(address) || strings.HasSuffix(key, "\x00"+normalizeUpstream(address)) {
			r.states[key] = updateHealth(state, healthy)
		}
	}
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
	mu         sync.Mutex
	registry   *HealthRegistry
	sites      []config.SiteConfig
	client     *http.Client
	parent     context.Context
	generation *healthGeneration
}

type healthGeneration struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
	if ctx == nil {
		ctx = context.Background()
	}
	h.mu.Lock()
	h.parent = ctx
	old := h.restartLocked()
	h.mu.Unlock()
	waitHealthGeneration(old)
}

// UpdateSites replaces the checker generation after the previous loops exit.
func (h *HealthChecker) UpdateSites(sites []config.SiteConfig) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.sites = append([]config.SiteConfig(nil), sites...)
	var old *healthGeneration
	if h.parent != nil {
		old = h.restartLocked()
	}
	h.mu.Unlock()
	waitHealthGeneration(old)
}

func (h *HealthChecker) restartLocked() *healthGeneration {
	old := h.generation
	ctx, cancel := context.WithCancel(h.parent)
	next := &healthGeneration{cancel: cancel}
	for _, site := range h.sites {
		if !site.WAF.HealthCheck.Enabled {
			continue
		}
		site := site
		next.wg.Add(1)
		go func() {
			defer next.wg.Done()
			h.loop(ctx, site)
		}()
	}
	h.generation = next
	return old
}

func waitHealthGeneration(generation *healthGeneration) {
	if generation == nil {
		return
	}
	generation.cancel()
	generation.wg.Wait()
}

func (h *HealthChecker) loop(ctx context.Context, site config.SiteConfig) {
	interval := site.WAF.HealthCheck.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	h.checkContext(ctx, site)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkContext(ctx, site)
		}
	}
}

func (h *HealthChecker) check(site config.SiteConfig) { h.checkContext(context.Background(), site) }
func (h *HealthChecker) checkContext(ctx context.Context, site config.SiteConfig) {
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
	var checks sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, upstream := range site.Upstreams {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			checks.Wait()
			return
		}
		checks.Add(1)
		go func(upstream config.UpstreamConfig) {
			defer checks.Done()
			defer func() { <-slots }()
			rawURL, _ := url.Parse(strings.TrimSpace(upstream.Address))
			target := normalizeUpstream(upstream.Address)
			u, err := url.Parse(target)
			if err != nil {
				if ctx.Err() == nil {
					h.registry.SetForSite(site.ID, upstream.Address, false)
				}
				return
			}
			u.Path = path
			var resp *http.Response
			if rawURL != nil && (strings.EqualFold(rawURL.Scheme, "ws") || strings.EqualFold(rawURL.Scheme, "wss")) {
				request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
				if requestErr != nil {
					if ctx.Err() == nil {
						h.registry.SetForSite(site.ID, upstream.Address, false)
					}
					return
				}
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "websocket")
				request.Header.Set("Sec-WebSocket-Version", "13")
				request.Header.Set("Sec-WebSocket-Key", "Y2hlZXNld2FmLWhlYWx0aA==")
				resp, err = client.Do(request)
			} else {
				request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
				if requestErr != nil {
					return
				}
				resp, err = client.Do(request)
			}
			if err != nil {
				if ctx.Err() == nil {
					h.registry.SetForSite(site.ID, upstream.Address, false)
				}
				return
			}
			_ = netguard.DrainAndClose(resp.Body)
			healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
			if rawURL != nil && (strings.EqualFold(rawURL.Scheme, "ws") || strings.EqualFold(rawURL.Scheme, "wss")) {
				healthy = resp.StatusCode == http.StatusSwitchingProtocols
			}
			if ctx.Err() == nil {
				h.registry.SetForSite(site.ID, upstream.Address, healthy)
			}
		}(upstream)
	}
	checks.Wait()
}

func (r *HealthRegistry) addUpstream(address string, cfg config.HealthCheckConfig) {
	key := address
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
	address = strings.TrimSpace(address)
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	if parsed, err := url.Parse(address); err == nil {
		switch strings.ToLower(parsed.Scheme) {
		case "ws":
			parsed.Scheme = "http"
		case "wss":
			parsed.Scheme = "https"
		}
		return parsed.String()
	}
	return address
}
