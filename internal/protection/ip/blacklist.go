package ip

import (
	"net/netip"
	"strings"
)

type Matcher struct {
	ips      map[netip.Addr]struct{}
	prefixes []netip.Prefix
	cidrs    prefixIndex[struct{}]
}

func NewMatcher(entries []string) (*Matcher, error) {
	m := &Matcher{ips: map[netip.Addr]struct{}{}}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, err
			}
			prefix, err = canonicalPrefix(prefix)
			if err != nil {
				return nil, err
			}
			m.prefixes = append(m.prefixes, prefix)
			m.cidrs.add(prefix, struct{}{})
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			continue
		}
		m.ips[addr.Unmap()] = struct{}{}
	}
	return m, nil
}

func (m *Matcher) Contains(raw string) bool {
	if m == nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if _, ok := m.ips[addr]; ok {
		return true
	}
	return len(m.cidrs.match(addr)) > 0
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
