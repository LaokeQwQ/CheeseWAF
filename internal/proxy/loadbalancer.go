package proxy

import (
	"hash/fnv"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type LoadBalancer struct {
	mu       sync.RWMutex
	next     map[string]uint64
	inflight map[string]int
	sites    []config.SiteConfig
	byHost   map[string]config.SiteConfig
	health   *HealthRegistry
}

func NewLoadBalancer(sites []config.SiteConfig) *LoadBalancer {
	lb := &LoadBalancer{
		next:     map[string]uint64{},
		inflight: map[string]int{},
		sites:    sites,
	}
	lb.rebuildHostIndexLocked()
	return lb
}

func (lb *LoadBalancer) WithHealth(health *HealthRegistry) *LoadBalancer {
	lb.health = health
	return lb
}

func (lb *LoadBalancer) UpdateSites(sites []config.SiteConfig, health *HealthRegistry) {
	if lb == nil {
		return
	}
	lb.mu.Lock()
	lb.sites = append([]config.SiteConfig(nil), sites...)
	lb.health = health
	lb.next = map[string]uint64{}
	lb.inflight = map[string]int{}
	lb.rebuildHostIndexLocked()
	lb.mu.Unlock()
}

// SiteForHost returns the enabled site whose Domains contain host (port stripped).
// When no site matches, it returns an empty SiteConfig (ID == "") so callers can
// reject the request instead of falling back to another tenant's site.
func (lb *LoadBalancer) SiteForHost(host string) config.SiteConfig {
	host = normalizeRequestHost(host)
	if lb == nil {
		return config.SiteConfig{}
	}
	lb.mu.RLock()
	site, ok := lb.byHost[host]
	lb.mu.RUnlock()
	if ok {
		return site
	}
	return config.SiteConfig{}
}

func normalizeRequestHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return strings.TrimSpace(parsed)
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimSpace(host[1 : len(host)-1])
	}
	return host
}

func (lb *LoadBalancer) rebuildHostIndexLocked() {
	index := make(map[string]config.SiteConfig, len(lb.sites)*2)
	for _, site := range lb.sites {
		if !site.Enabled {
			continue
		}
		for _, domain := range site.Domains {
			key := normalizeRequestHost(domain)
			if key == "" {
				continue
			}
			// First enabled site wins for a domain (stable with previous linear scan).
			if _, exists := index[key]; !exists {
				index[key] = site
			}
		}
	}
	lb.byHost = index
}

func (lb *LoadBalancer) Next(site config.SiteConfig, clientIP string) (*url.URL, error) {
	return lb.nextExcluding(site, clientIP, nil)
}

func (lb *LoadBalancer) nextExcluding(site config.SiteConfig, clientIP string, skip map[string]struct{}) (*url.URL, error) {
	candidates := lb.healthyUpstreams(site)
	if len(skip) > 0 {
		filtered := make([]config.UpstreamConfig, 0, len(candidates))
		for _, candidate := range candidates {
			if _, skipped := skip[normalizeUpstream(candidate.Address)]; skipped {
				continue
			}
			filtered = append(filtered, candidate)
		}
		candidates = filtered
	}
	if len(candidates) == 0 {
		return nil, ErrNoUpstream
	}
	index := 0
	mode := strings.ToLower(strings.TrimSpace(site.LoadBalance))
	switch mode {
	case "weighted":
		var total uint64
		for _, candidate := range candidates {
			total += normalizedWeight(candidate.Weight)
		}
		if total == 0 {
			return nil, ErrNoUpstream
		}
		lb.mu.Lock()
		cursor := lb.next[site.ID] % total
		lb.next[site.ID] = cursor + 1
		lb.mu.Unlock()
		var cumulative uint64
		for i, candidate := range candidates {
			cumulative += normalizedWeight(candidate.Weight)
			if cursor < cumulative {
				index = i
				break
			}
		}
	case "ip_hash":
		if clientIP != "" {
			index = ipHashIndex(clientIP, candidates)
		} else {
			lb.mu.Lock()
			index = int(lb.next[site.ID] % uint64(len(candidates)))
			lb.next[site.ID] = uint64(index + 1)
			lb.mu.Unlock()
		}
	case "least_conn":
		index = lb.leastConnIndex(candidates)
	default:
		lb.mu.Lock()
		index = int(lb.next[site.ID] % uint64(len(candidates)))
		lb.next[site.ID] = uint64(index + 1)
		lb.mu.Unlock()
	}
	target := candidates[index].Address
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	return url.Parse(target)
}

// Track records one in-flight request for least_conn. The returned function
// must be called exactly once when the attempt finishes.
func (lb *LoadBalancer) Track(target *url.URL) func() {
	if lb == nil || target == nil {
		return func() {}
	}
	key := upstreamKeyFromURL(target)
	if key == "" {
		return func() {}
	}
	lb.mu.Lock()
	if lb.inflight == nil {
		lb.inflight = map[string]int{}
	}
	lb.inflight[key]++
	lb.mu.Unlock()
	return func() {
		lb.mu.Lock()
		if n := lb.inflight[key]; n > 1 {
			lb.inflight[key] = n - 1
		} else {
			delete(lb.inflight, key)
		}
		lb.mu.Unlock()
	}
}

func (lb *LoadBalancer) leastConnIndex(candidates []config.UpstreamConfig) int {
	if len(candidates) == 0 {
		return 0
	}
	lb.mu.Lock()
	defer lb.mu.Unlock()
	best := 0
	bestLoad := lb.inflightLocked(candidates[0].Address)
	for i := 1; i < len(candidates); i++ {
		load := lb.inflightLocked(candidates[i].Address)
		if load < bestLoad {
			best = i
			bestLoad = load
		}
	}
	return best
}

func (lb *LoadBalancer) inflightLocked(address string) int {
	if lb.inflight == nil {
		return 0
	}
	return lb.inflight[normalizeUpstream(address)]
}

func ipHashIndex(clientIP string, candidates []config.UpstreamConfig) int {
	if len(candidates) == 0 {
		return 0
	}
	best := 0
	bestScore := rendezvousScore(clientIP, candidates[0].Address)
	for i := 1; i < len(candidates); i++ {
		score := rendezvousScore(clientIP, candidates[i].Address)
		if score > bestScore {
			best = i
			bestScore = score
		}
	}
	return best
}

func rendezvousScore(clientIP, address string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(clientIP))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(normalizeUpstream(address)))
	return h.Sum64()
}

func upstreamKeyFromURL(target *url.URL) string {
	if target == nil {
		return ""
	}
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return ""
	}
	scheme := strings.TrimSpace(target.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	return normalizeUpstream(scheme + "://" + host)
}

func (lb *LoadBalancer) healthyUpstreams(site config.SiteConfig) []config.UpstreamConfig {
	lb.mu.RLock()
	health := lb.health
	lb.mu.RUnlock()
	out := make([]config.UpstreamConfig, 0, len(site.Upstreams))
	for _, upstream := range site.Upstreams {
		if health != nil && !health.Healthy(upstream.Address) {
			continue
		}
		out = append(out, upstream)
	}
	if len(out) == 0 && len(site.Upstreams) > 0 {
		out = append(out, site.Upstreams...)
	}
	return out
}

func normalizedWeight(weight int) uint64 {
	if weight <= 0 {
		return 1
	}
	return uint64(weight)
}
