package proxy

import (
	"net/url"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type LoadBalancer struct {
	mu     sync.RWMutex
	next   map[string]int
	sites  []config.SiteConfig
	byHost map[string]config.SiteConfig
	health *HealthRegistry
}

func NewLoadBalancer(sites []config.SiteConfig) *LoadBalancer {
	lb := &LoadBalancer{next: map[string]int{}, sites: sites}
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
	lb.next = map[string]int{}
	lb.rebuildHostIndexLocked()
	lb.mu.Unlock()
}

// SiteForHost returns the enabled site whose Domains contain host (port stripped).
// When no site matches, it returns an empty SiteConfig (ID == "") so callers can
// reject the request instead of falling back to another tenant's site.
func (lb *LoadBalancer) SiteForHost(host string) config.SiteConfig {
	host = strings.Split(strings.ToLower(host), ":")[0]
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

func (lb *LoadBalancer) rebuildHostIndexLocked() {
	index := make(map[string]config.SiteConfig, len(lb.sites)*2)
	for _, site := range lb.sites {
		if !site.Enabled {
			continue
		}
		for _, domain := range site.Domains {
			key := strings.ToLower(strings.TrimSpace(domain))
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
	candidates := lb.healthyUpstreams(site)
	if len(candidates) == 0 {
		return nil, ErrNoUpstream
	}
	index := 0
	mode := strings.ToLower(strings.TrimSpace(site.LoadBalance))
	switch mode {
	case "ip_hash":
		if clientIP != "" {
			for _, r := range clientIP {
				index += int(r)
			}
			index %= len(candidates)
		}
	case "least_conn":
		// Approximate least-connections via rotating preference weighted by inverse of recent picks.
		lb.mu.Lock()
		index = lb.next[site.ID] % len(candidates)
		// Prefer lower slot under a simple expanding window.
		if len(candidates) > 1 {
			second := (index + 1) % len(candidates)
			if lb.next[site.ID+":slot:"+candidates[second].Address] < lb.next[site.ID+":slot:"+candidates[index].Address] {
				index = second
			}
		}
		lb.next[site.ID+":slot:"+candidates[index].Address]++
		lb.next[site.ID] = index + 1
		lb.mu.Unlock()
	default:
		lb.mu.Lock()
		index = lb.next[site.ID] % len(candidates)
		lb.next[site.ID] = index + 1
		lb.mu.Unlock()
	}
	target := candidates[index].Address
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	return url.Parse(target)
}

func (lb *LoadBalancer) healthyUpstreams(site config.SiteConfig) []config.UpstreamConfig {
	var out []config.UpstreamConfig
	for _, upstream := range site.Upstreams {
		if lb.health != nil && !lb.health.Healthy(upstream.Address) {
			continue
		}
		weight := upstream.Weight
		if weight <= 0 || site.LoadBalance != "weighted" {
			weight = 1
		}
		for i := 0; i < weight; i++ {
			out = append(out, upstream)
		}
	}
	if len(out) == 0 && len(site.Upstreams) > 0 {
		out = append(out, site.Upstreams...)
	}
	return out
}
