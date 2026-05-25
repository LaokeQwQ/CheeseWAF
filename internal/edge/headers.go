// Package edge applies request header, cache, and compression policies.
package edge

import (
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type HeaderModifier struct {
	enabled bool
	rules   []config.HeaderRuleConfig
}

func NewHeaderModifier(cfg config.HeaderPolicyConfig) *HeaderModifier {
	return &HeaderModifier{enabled: cfg.Enabled, rules: cfg.Rules}
}

func (m *HeaderModifier) Apply(r *http.Request) {
	if m == nil || !m.enabled || r == nil {
		return
	}
	for _, rule := range m.rules {
		if !rule.Enabled || rule.Header == "" {
			continue
		}
		if rule.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, rule.PathPrefix) {
			continue
		}
		switch strings.ToLower(rule.Operation) {
		case "add":
			r.Header.Add(rule.Header, rule.Value)
		case "delete":
			r.Header.Del(rule.Header)
		default:
			r.Header.Set(rule.Header, rule.Value)
		}
	}
}
