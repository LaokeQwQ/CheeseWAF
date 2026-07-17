package acl

import (
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"net/http/httptest"
	"testing"
)

func TestPolicyEvaluateMatchesCombinedConditions(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{ID: "admin", Name: "admin API", Method: "post", PathPrefix: "/admin", Header: "X-Role", HeaderValue: "Operator", Action: "block", Severity: "high", Enabled: true}}})
	req := httptest.NewRequest("post", "https://example.test/admin/users?active=1", nil)
	req.Header.Set("X-Role", "site-OPERATOR-primary")
	result := policy.Evaluate(req)
	if result == nil {
		t.Fatal("result = nil")
	}
	if result.DetectorID != "acl.admin" || result.Action != engine.ActionBlock || result.Severity != engine.SeverityHigh || result.Payload != "post /admin/users?active=1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestPolicyEvaluateSkipsNonMatchingRules(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{ID: "disabled", Method: "GET", Enabled: false}, {ID: "method", Method: "DELETE", Enabled: true}, {ID: "path", Method: "GET", PathPrefix: "/private", Enabled: true}, {ID: "header", Method: "GET", Header: "X-Token", Enabled: true}}})
	if result := policy.Evaluate(httptest.NewRequest("GET", "https://example.test/public", nil)); result != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestPolicyEvaluateUsesFirstMatchingRule(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{ID: "first", Action: "log", Severity: "low", Enabled: true}, {ID: "second", Action: "block", Severity: "critical", Enabled: true}}})
	result := policy.Evaluate(httptest.NewRequest("GET", "https://example.test/", nil))
	if result == nil || result.DetectorID != "acl.first" || result.Action != engine.ActionLog || result.Severity != engine.SeverityLow {
		t.Fatalf("result = %#v", result)
	}
}

func TestPolicyEvaluateHandlesInactiveInputs(t *testing.T) {
	var nilPolicy *Policy
	req := httptest.NewRequest("GET", "https://example.test/", nil)
	if nilPolicy.Evaluate(req) != nil || NewPolicy(config.ACLProtectionConfig{}).Evaluate(req) != nil || NewPolicy(config.ACLProtectionConfig{Enabled: true}).Evaluate(nil) != nil {
		t.Fatal("inactive input matched")
	}
}
