package ip

import (
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	AccessActionAllow = "allow"
	AccessActionBlock = "block"
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
	rules []accessRule
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
	policy := &AccessPolicy{}
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
		policy.rules = append(policy.rules, rule)
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
		policy.rules = append(policy.rules, rule)
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
			policy.rules = append(policy.rules, rule)
		}
	}
	return policy, nil
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
	var allow AccessDecision
	var allowScore int
	var block AccessDecision
	var blockScore int
	for _, rule := range p.rules {
		if !rule.applies(clientIP, siteID, path) {
			continue
		}
		decision := rule.decision()
		score := rule.specificity()
		switch rule.action {
		case AccessActionAllow:
			if !allow.Matched || score > allowScore {
				allow = decision
				allowScore = score
			}
		case AccessActionBlock:
			if !block.Matched || score > blockScore {
				block = decision
				blockScore = score
			}
		}
	}
	if allow.Matched {
		return allow
	}
	if block.Matched {
		return block
	}
	return AccessDecision{Action: "none"}
}

func (r accessRule) applies(clientIP, siteID, path string) bool {
	if r.matcher == nil || !r.matcher.Contains(clientIP) {
		return false
	}
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

func (r accessRule) specificity() int {
	switch r.scope {
	case "path":
		return 3000 + len(r.pathPrefix)
	case "site":
		return 2000
	default:
		return 1000
	}
}

func normalizeAccessAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case AccessActionBlock:
		return AccessActionBlock
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
