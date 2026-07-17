package proxy

import (
	"net/url"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type LoadBalancer struct {
	mu     sync.Mutex
	next   map[string]int
	sites  []config.SiteConfig
	health *HealthRegistry
}

func NewLoadBalancer(sites []config.SiteConfig) *LoadBalancer {
	return &LoadBalancer{next: map[string]int{}, sites: sites}
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
	lb.mu.Lock()
	sites := lb.sites
	lb.mu.Unlock()
	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		for _, domain := range site.Domains {
			if strings.EqualFold(host, domain) {
				return site
			}
		}
	}
	return config.SiteConfig{}
}

func (lb *LoadBalancer) Next(site config.SiteConfig, clientIP string) (*url.URL, error) {
	candidates := lb.healthyUpstreams(site)
	if len(candidates) == 0 {
		return nil, ErrNoUpstream
	}
	index := 0
	if site.LoadBalance == "ip_hash" && clientIP != "" {
		for _, r := range clientIP {
			index += int(r)
		}
		index %= len(candidates)
	} else {
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
