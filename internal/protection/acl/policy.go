// Package acl implements method, path, and header access control.
package acl

import (
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/rules"
)

type Rule struct {
	ID          string
	Name        string
	Method      string
	PathPrefix  string
	Header      string
	HeaderValue string
	Action      engine.Action
	Severity    engine.Severity
	Enabled     bool
}

type Policy struct {
	enabled bool
	rules   []Rule
}

func NewPolicy(cfg config.ACLProtectionConfig) *Policy {
	policy := &Policy{enabled: cfg.Enabled}
	for _, item := range cfg.Rules {
		method := strings.ToUpper(strings.TrimSpace(item.Method))
		pathPrefix := strings.TrimSpace(item.PathPrefix)
		header := strings.TrimSpace(item.Header)
		headerValue := strings.TrimSpace(item.HeaderValue)
		if !item.Enabled || (method == "" && pathPrefix == "" && header == "") || (header == "" && headerValue != "") {
			continue
		}
		policy.rules = append(policy.rules, Rule{
			ID:          item.ID,
			Name:        item.Name,
			Method:      method,
			PathPrefix:  pathPrefix,
			Header:      header,
			HeaderValue: headerValue,
			Action:      rules.ParseAction(item.Action),
			Severity:    rules.ParseSeverity(item.Severity),
			Enabled:     item.Enabled,
		})
	}
	return policy
}

func (p *Policy) Evaluate(r *http.Request) *engine.DetectionResult {
	if p == nil || !p.enabled || r == nil {
		return nil
	}
	for _, rule := range p.rules {
		if !rule.Enabled || !rule.matches(r) {
			continue
		}
		return &engine.DetectionResult{
			Detected:   true,
			DetectorID: "acl." + rule.ID,
			Category:   "acl",
			Severity:   rule.Severity,
			Action:     rule.Action,
			Message:    "ACL rule matched: " + rule.Name,
			Confidence: 1,
			Payload:    r.Method + " " + r.URL.RequestURI(),
		}
	}
	return nil
}

func (r Rule) matches(req *http.Request) bool {
	if r.Method != "" && r.Method != strings.ToUpper(req.Method) {
		return false
	}
	if r.PathPrefix != "" && !strings.HasPrefix(req.URL.Path, r.PathPrefix) {
		return false
	}
	if r.Header != "" {
		for _, value := range req.Header.Values(r.Header) {
			value = strings.TrimSpace(value)
			if r.HeaderValue == "" && value != "" {
				return true
			}
			if r.HeaderValue != "" && strings.EqualFold(value, r.HeaderValue) {
				return true
			}
		}
		return false
	}
	return true
}
