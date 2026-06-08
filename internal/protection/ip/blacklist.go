package ip

import (
	"net"
	"strings"
)

type Matcher struct {
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

func NewMatcher(entries []string) (*Matcher, error) {
	m := &Matcher{ips: map[string]struct{}{}}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, err
			}
			m.cidrs = append(m.cidrs, network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			continue
		}
		m.ips[ip.String()] = struct{}{}
	}
	return m, nil
}

func (m *Matcher) Contains(raw string) bool {
	if m == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	if _, ok := m.ips[ip.String()]; ok {
		return true
	}
	for _, network := range m.cidrs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

type Blacklist struct {
	matcher *Matcher
}

func NewBlacklist(entries []string) (*Blacklist, error) {
	matcher, err := NewMatcher(entries)
	if err != nil {
		return nil, err
	}
	return &Blacklist{matcher: matcher}, nil
}

func (b *Blacklist) Blocked(ip string) bool {
	return b != nil && b.matcher.Contains(ip)
}
