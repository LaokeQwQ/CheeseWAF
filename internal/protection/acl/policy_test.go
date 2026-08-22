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
	req.Header.Add("X-Role", "viewer")
	req.Header.Add("X-Role", "OPERATOR")
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
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{ID: "first", Method: "GET", Action: "log", Severity: "low", Enabled: true}, {ID: "second", Method: "GET", Action: "block", Severity: "critical", Enabled: true}}})
	result := policy.Evaluate(httptest.NewRequest("GET", "https://example.test/", nil))
	if result == nil || result.DetectorID != "acl.first" || result.Action != engine.ActionLog || result.Severity != engine.SeverityLow {
		t.Fatalf("result = %#v", result)
	}
}

func TestPolicyEvaluateDoesNotSubstringMatchHeaderValue(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{{ID: "role", Header: "X-Role", HeaderValue: "operator", Action: "block", Enabled: true}}})
	req := httptest.NewRequest("GET", "https://example.test/", nil)
	req.Header.Set("X-Role", "site-operator-primary")
	if result := policy.Evaluate(req); result != nil {
		t.Fatalf("substring header value matched: %#v", result)
	}
}

func TestPolicyEvaluateIgnoresAmbiguousRules(t *testing.T) {
	policy := NewPolicy(config.ACLProtectionConfig{Enabled: true, Rules: []config.ACLRuleConfig{
		{ID: "empty", Action: "block", Enabled: true},
		{ID: "value-without-header", HeaderValue: "secret", Action: "block", Enabled: true},
	}})
	if result := policy.Evaluate(httptest.NewRequest("GET", "https://example.test/", nil)); result != nil {
		t.Fatalf("ambiguous ACL rule matched: %#v", result)
	}
}

func TestPolicyEvaluateHandlesInactiveInputs(t *testing.T) {
	var nilPolicy *Policy
	req := httptest.NewRequest("GET", "https://example.test/", nil)
	if nilPolicy.Evaluate(req) != nil || NewPolicy(config.ACLProtectionConfig{}).Evaluate(req) != nil || NewPolicy(config.ACLProtectionConfig{Enabled: true}).Evaluate(nil) != nil {
		t.Fatal("inactive input matched")
	}
}
