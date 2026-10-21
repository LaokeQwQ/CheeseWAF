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
	if p == nil || !p.enabled || r == nil || r.URL == nil {
		return nil
	}
	cleaned, valid := engine.NormalizeRequestPath(r.URL.Path)
	if !valid {
		return nil
	}
	paths := []string{cleaned}
	if strings.ContainsAny(r.URL.Path, ";%") {
		paths, valid = engine.SecurityPathViews(r.URL.Path)
		if !valid {
			return nil
		}
		// Derive matrix routing before Clean can remove its path segment.
		// Keep the old cleaned view, without adding raw dot-path matches.
		if r.URL.Path != cleaned {
			paths = paths[1:]
		}
	}
	var selected *Rule
	for _, path := range paths {
		for i := range p.rules {
			rule := &p.rules[i]
			if !rule.Enabled || !rule.matches(r, path) {
				continue
			}
			// Preserve first-match ordering within each interpretation. A new
			// log-only view must not hide a block from an existing path view.
			if selected == nil || actionRank(rule.Action) > actionRank(selected.Action) {
				selected = rule
			}
			break
		}
	}
	if selected == nil {
		return nil
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "acl." + selected.ID,
		Category:   "acl",
		Severity:   selected.Severity,
		Action:     selected.Action,
		Message:    "ACL rule matched: " + selected.Name,
		Confidence: 1,
		Payload:    r.Method + " " + r.URL.RequestURI(),
	}
}

func actionRank(action engine.Action) int {
	switch action {
	case engine.ActionBlock:
		return 3
	case engine.ActionChallenge:
		return 2
	case engine.ActionLog:
		return 1
	default:
		return 0
	}
}

func (r Rule) matches(req *http.Request, path string) bool {
	if r.Method != "" && r.Method != strings.ToUpper(req.Method) {
		return false
	}
	if r.PathPrefix != "" && !engine.PathMatchesPrefix(path, r.PathPrefix) {
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
