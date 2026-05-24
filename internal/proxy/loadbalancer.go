package proxy

import (
	"net/url"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type LoadBalancer struct {
	mu    sync.Mutex
	next  map[string]int
	sites []config.SiteConfig
}

func NewLoadBalancer(sites []config.SiteConfig) *LoadBalancer {
	return &LoadBalancer{next: map[string]int{}, sites: sites}
}

func (lb *LoadBalancer) SiteForHost(host string) config.SiteConfig {
	host = strings.Split(strings.ToLower(host), ":")[0]
	for _, site := range lb.sites {
		if !site.Enabled {
			continue
		}
		for _, domain := range site.Domains {
			if strings.EqualFold(host, domain) {
				return site
			}
		}
	}
	for _, site := range lb.sites {
		if site.Enabled {
			return site
		}
	}
	return config.SiteConfig{}
}

func (lb *LoadBalancer) Next(site config.SiteConfig, clientIP string) (*url.URL, error) {
	if len(site.Upstreams) == 0 {
		return nil, ErrNoUpstream
	}
	index := 0
	if site.LoadBalance == "ip_hash" && clientIP != "" {
		for _, r := range clientIP {
			index += int(r)
		}
		index %= len(site.Upstreams)
	} else {
		lb.mu.Lock()
		index = lb.next[site.ID] % len(site.Upstreams)
		lb.next[site.ID] = index + 1
		lb.mu.Unlock()
	}
	target := site.Upstreams[index].Address
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	return url.Parse(target)
}
