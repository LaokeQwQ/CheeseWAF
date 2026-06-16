package ip

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestAccessPolicyAllowOverridesBlock(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{
		Blacklist: []string{"203.0.113.10"},
		AccessRules: []config.IPAccessRuleConfig{
			{ID: "allow-site", Action: "allow", Scope: "site", SiteID: "site-a", Entries: []string{"203.0.113.10"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	decision := policy.Evaluate("203.0.113.10", "site-a", "/")
	if !decision.Matched || decision.Action != AccessActionAllow || decision.RuleID != "allow-site" {
		t.Fatalf("expected allow override, got %+v", decision)
	}
}

func TestAccessPolicyPathScope(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{
		AccessRules: []config.IPAccessRuleConfig{
			{ID: "block-admin", Action: "block", Scope: "path", SiteID: "site-a", PathPrefix: "/admin", Entries: []string{"203.0.113.0/24"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if decision := policy.Evaluate("203.0.113.10", "site-a", "/admin/users"); decision.Action != AccessActionBlock {
		t.Fatalf("expected path block, got %+v", decision)
	}
	if decision := policy.Evaluate("203.0.113.10", "site-a", "/public"); decision.Matched {
		t.Fatalf("expected no match outside path, got %+v", decision)
	}
	if decision := policy.Evaluate("203.0.113.10", "site-b", "/admin/users"); decision.Matched {
		t.Fatalf("expected no match outside site, got %+v", decision)
	}
}

func TestAccessPolicySiteScope(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{
		AccessRules: []config.IPAccessRuleConfig{
			{ID: "block-site", Action: "block", Scope: "site", SiteID: "site-a", Entries: []string{"198.51.100.7"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if decision := policy.Evaluate("198.51.100.7", "site-a", "/"); decision.Action != AccessActionBlock {
		t.Fatalf("expected site block, got %+v", decision)
	}
	if decision := policy.Evaluate("198.51.100.7", "site-b", "/"); decision.Matched {
		t.Fatalf("expected no match outside site, got %+v", decision)
	}
}

func TestAccessPolicyMonitorDoesNotOverrideAllowOrBlock(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{
		AccessRules: []config.IPAccessRuleConfig{
			{ID: "monitor-global", Action: "monitor", Scope: "global", Entries: []string{"203.0.113.10"}, Enabled: true},
			{ID: "block-admin", Action: "block", Scope: "path", SiteID: "site-a", PathPrefix: "/admin", Entries: []string{"203.0.113.10"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if decision := policy.Evaluate("203.0.113.10", "site-a", "/"); !decision.Matched || decision.Action != AccessActionMonitor {
		t.Fatalf("expected monitor match, got %+v", decision)
	}
	if decision := policy.Evaluate("203.0.113.10", "site-a", "/admin"); decision.Action != AccessActionBlock {
		t.Fatalf("expected block to override monitor on path, got %+v", decision)
	}
}
