package ip

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestAccessPolicyMatrixBlockKeepsAllInterpretations(t *testing.T) {
	for _, prefix := range []string{"/admin", "/admin;v=1"} {
		t.Run(prefix, func(t *testing.T) {
			policy, err := NewAccessPolicy(config.IPProtectionConfig{AccessRules: []config.IPAccessRuleConfig{{
				ID: "deny", Action: "block", Scope: "path", PathPrefix: prefix,
				Entries: []string{"203.0.113.10"}, Enabled: true,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			decision := policy.Evaluate("203.0.113.10", "site-a", "/admin;v=1/panel")
			if decision.Action != AccessActionBlock || decision.RuleID != "deny" {
				t.Fatalf("block for %q lost a request interpretation: %+v", prefix, decision)
			}
		})
	}
}

func TestAccessPolicyMatrixAllowRequiresEveryInterpretation(t *testing.T) {
	for _, prefix := range []string{"/public", "/public;v=1"} {
		t.Run(prefix, func(t *testing.T) {
			policy, err := NewAccessPolicy(config.IPProtectionConfig{AccessRules: []config.IPAccessRuleConfig{{
				ID: "allow", Action: "allow", Scope: "path", PathPrefix: prefix,
				Entries: []string{"203.0.113.10"}, Enabled: true,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			decision := policy.Evaluate("203.0.113.10", "site-a", "/public;v=1/page")
			if decision.Action == AccessActionAllow {
				t.Fatalf("one path view must not exempt the other: %+v", decision)
			}
		})
	}
}

func TestAccessPolicyPathSpecificityIsResolvedWithinEachView(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{
		Blacklist: []string{"203.0.113.10"},
		AccessRules: []config.IPAccessRuleConfig{
			{ID: "allow-literal", Action: "allow", Scope: "path", PathPrefix: "/public;v=1", Entries: []string{"203.0.113.10"}, Enabled: true},
			{ID: "allow-routed", Action: "allow", Scope: "path", PathPrefix: "/public", Entries: []string{"203.0.113.10"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.Evaluate("203.0.113.10", "site-a", "/public;v=1/page"); got.Action != AccessActionAllow {
		t.Fatalf("specific allows for every interpretation must still override global block: %+v", got)
	}
	if got := policy.Evaluate("203.0.113.10", "site-a", "/private"); got.Action != AccessActionBlock {
		t.Fatalf("global block must remain effective elsewhere: %+v", got)
	}
}

func TestAccessPolicyMatrixAlternateBlockCannotBeHiddenByLiteralAllow(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{AccessRules: []config.IPAccessRuleConfig{
		{ID: "allow-literal", Action: "allow", Scope: "path", PathPrefix: "/admin;v=1", Entries: []string{"203.0.113.10"}, Enabled: true},
		{ID: "block-routed", Action: "block", Scope: "path", PathPrefix: "/admin", Entries: []string{"203.0.113.10"}, Enabled: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.Evaluate("203.0.113.10", "site-a", "/admin;v=1/panel"); got.Action != AccessActionBlock || got.RuleID != "block-routed" {
		t.Fatalf("literal allow hid routed-view block: %+v", got)
	}
}

func TestAccessPolicyMatrixRoutingPrecedesDotCollapse(t *testing.T) {
	policy, err := NewAccessPolicy(config.IPProtectionConfig{AccessRules: []config.IPAccessRuleConfig{{
		ID: "deny", Action: "block", Scope: "path", PathPrefix: "/admin",
		Entries: []string{"203.0.113.10"}, Enabled: true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.Evaluate("203.0.113.10", "site-a", "/public/.;v=1/../admin/panel"); got.Action != AccessActionBlock {
		t.Fatalf("Clean hid the matrix routing interpretation: %+v", got)
	}
}
