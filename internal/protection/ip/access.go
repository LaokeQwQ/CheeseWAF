package ip

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	AccessActionAllow   = "allow"
	AccessActionBlock   = "block"
	AccessActionMonitor = "monitor"
)

type AccessDecision struct {
	Matched     bool   `json:"matched"`
	Action      string `json:"action"`
	RuleID      string `json:"rule_id,omitempty"`
	RuleName    string `json:"rule_name,omitempty"`
	Scope       string `json:"scope,omitempty"`
	SiteID      string `json:"site_id,omitempty"`
	PathPrefix  string `json:"path_prefix,omitempty"`
	Description string `json:"description,omitempty"`
}

type AccessPolicy struct {
	rules    []accessRule
	exact    map[netip.Addr][]int
	networks prefixIndex[int]
}

type accessRule struct {
	id          string
	name        string
	description string
	action      string
	scope       string
	siteID      string
	pathPrefix  string
	matcher     *Matcher
}

func NewAccessPolicy(cfg config.IPProtectionConfig) (*AccessPolicy, error) {
	policy := &AccessPolicy{exact: make(map[netip.Addr][]int)}
	if len(cfg.Whitelist) > 0 {
		rule, err := newAccessRule(config.IPAccessRuleConfig{
			ID:      "legacy-whitelist",
			Name:    "Global allowlist",
			Action:  AccessActionAllow,
			Scope:   "global",
			Entries: cfg.Whitelist,
			Enabled: true,
		})
		if err != nil {
			return nil, err
		}
		policy.addRule(rule)
	}
	if len(cfg.Blacklist) > 0 {
		rule, err := newAccessRule(config.IPAccessRuleConfig{
			ID:      "legacy-blacklist",
			Name:    "Global blocklist",
			Action:  AccessActionBlock,
			Scope:   "global",
			Entries: cfg.Blacklist,
			Enabled: true,
		})
		if err != nil {
			return nil, err
		}
		policy.addRule(rule)
	}
	for _, item := range cfg.AccessRules {
		if !item.Enabled {
			continue
		}
		rule, err := newAccessRule(item)
		if err != nil {
			return nil, err
		}
		if rule.matcher != nil {
			policy.addRule(rule)
		}
	}
	return policy, nil
}

func (p *AccessPolicy) addRule(rule accessRule) {
	index := len(p.rules)
	p.rules = append(p.rules, rule)
	for addr := range rule.matcher.ips {
		p.exact[addr] = append(p.exact[addr], index)
	}
	for _, prefix := range rule.matcher.prefixes {
		p.networks.add(prefix, index)
	}
}

func newAccessRule(item config.IPAccessRuleConfig) (accessRule, error) {
	matcher, err := NewMatcher(item.Entries)
	if err != nil {
		return accessRule{}, err
	}
	return accessRule{
		id:          strings.TrimSpace(item.ID),
		name:        strings.TrimSpace(item.Name),
		description: strings.TrimSpace(item.Description),
		action:      normalizeAccessAction(item.Action),
		scope:       normalizeAccessScope(item.Scope),
		siteID:      strings.TrimSpace(item.SiteID),
		pathPrefix:  normalizePathPrefix(item.PathPrefix),
		matcher:     matcher,
	}, nil
}

func (p *AccessPolicy) Evaluate(clientIP, siteID, path string) AccessDecision {
	if p == nil {
		return AccessDecision{Action: "none"}
	}
	var best AccessDecision
	var bestScore int
	addr, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return AccessDecision{Action: "none"}
	}
	addr = addr.Unmap()
	indices := append([]int(nil), p.exact[addr]...)
	indices = append(indices, p.networks.match(addr)...)
	sort.Ints(indices)
	previous := -1
	for _, index := range indices {
		if index == previous {
			continue
		}
		previous = index
		rule := p.rules[index]
		if !rule.appliesScope(siteID, path) {
			continue
		}
		score := rule.specificity(addr)
		if !best.Matched || score > bestScore {
			best = rule.decision()
			bestScore = score
		}
	}
	if best.Matched {
		return best
	}
	return AccessDecision{Action: "none"}
}

func (r accessRule) appliesScope(siteID, path string) bool {
	switch r.scope {
	case "site":
		return r.siteID != "" && r.siteID == siteID
	case "path":
		if r.siteID != "" && r.siteID != siteID {
			return false
		}
		prefix := r.pathPrefix
		if prefix == "" {
			prefix = "/"
		}
		return strings.HasPrefix(path, prefix)
	default:
		return true
	}
}

func (r accessRule) decision() AccessDecision {
	return AccessDecision{
		Matched:     true,
		Action:      r.action,
		RuleID:      r.id,
		RuleName:    r.name,
		Scope:       r.scope,
		SiteID:      r.siteID,
		PathPrefix:  r.pathPrefix,
		Description: r.description,
	}
}

func (r accessRule) specificity(addr netip.Addr) int {
	addressScore := 0
	if _, exact := r.matcher.ips[addr]; exact {
		addressScore = addr.BitLen()
	}
	for _, prefix := range r.matcher.prefixes {
		if prefix.Contains(addr) && prefix.Bits() > addressScore {
			addressScore = prefix.Bits()
		}
	}
	switch r.scope {
	case "path":
		return 3000 + len(r.pathPrefix) + addressScore
	case "site":
		return 2000 + addressScore
	default:
		return 1000 + addressScore
	}
}

func normalizeAccessAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case AccessActionBlock:
		return AccessActionBlock
	case AccessActionMonitor:
		return AccessActionMonitor
	default:
		return AccessActionAllow
	}
}

func normalizeAccessScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "site":
		return "site"
	case "path", "directory":
		return "path"
	default:
		return "global"
	}
}

func normalizePathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		return "/" + prefix
	}
	return prefix
}
