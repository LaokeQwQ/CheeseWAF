package ip

import (
	"net"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type GeoIPPolicy struct {
	enabled bool
	blocked map[string]struct{}
	ranges  []countryRange
}

type countryRange struct {
	country string
	network *net.IPNet
}

func NewGeoIPPolicy(cfg config.GeoIPConfig) (*GeoIPPolicy, error) {
	policy := &GeoIPPolicy{
		enabled: cfg.Enabled,
		blocked: map[string]struct{}{},
	}
	for _, country := range cfg.BlockedCountries {
		country = strings.ToUpper(strings.TrimSpace(country))
		if country != "" {
			policy.blocked[country] = struct{}{}
		}
	}
	for country, cidrs := range cfg.CountryCIDRs {
		country = strings.ToUpper(strings.TrimSpace(country))
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}
			policy.ranges = append(policy.ranges, countryRange{country: country, network: network})
		}
	}
	return policy, nil
}

func (p *GeoIPPolicy) Country(clientIP string) string {
	if p == nil {
		return ""
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return ""
	}
	for _, item := range p.ranges {
		if item.network.Contains(ip) {
			return item.country
		}
	}
	return ""
}

func (p *GeoIPPolicy) Blocked(clientIP string) bool {
	if p == nil || !p.enabled || len(p.blocked) == 0 {
		return false
	}
	country := p.Country(clientIP)
	if country == "" {
		return false
	}
	_, blocked := p.blocked[country]
	return blocked
}
