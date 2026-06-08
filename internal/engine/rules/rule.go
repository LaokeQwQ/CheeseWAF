// Package rules implements configurable request matching for CheeseWAF.
package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Rule struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Location string
	Action   engine.Action
	Severity engine.Severity
	Priority int
	Enabled  bool
}

func FromConfig(items []config.CustomRuleConfig) ([]Rule, error) {
	out := make([]Rule, 0, len(items))
	for _, item := range items {
		rule, err := compile(item.ID, item.Name, item.Pattern, item.Location, item.Action, item.Severity, item.Priority, item.Enabled)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func FromStorage(items []storage.Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(items))
	for _, item := range items {
		rule, err := compile(item.ID, item.Name, item.Pattern, item.Location, item.Action, item.Severity, item.Priority, item.Enabled)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func compile(id, name, pattern, location, action, severity string, priority int, enabled bool) (Rule, error) {
	if id == "" {
		id = name
	}
	if location == "" {
		location = "uri"
	}
	if priority == 0 {
		priority = 200
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("compile rule %q: %w", id, err)
	}
	return Rule{
		ID:       id,
		Name:     name,
		Pattern:  re,
		Location: strings.ToLower(location),
		Action:   ParseAction(action),
		Severity: ParseSeverity(severity),
		Priority: priority,
		Enabled:  enabled,
	}, nil
}

func ParseAction(action string) engine.Action {
	switch strings.ToLower(action) {
	case "log", "monitor":
		return engine.ActionLog
	case "challenge":
		return engine.ActionChallenge
	case "pass", "allow":
		return engine.ActionPass
	default:
		return engine.ActionBlock
	}
}

func ParseSeverity(severity string) engine.Severity {
	switch strings.ToLower(severity) {
	case "critical":
		return engine.SeverityCritical
	case "high":
		return engine.SeverityHigh
	case "low":
		return engine.SeverityLow
	case "info":
		return engine.SeverityInfo
	default:
		return engine.SeverityMedium
	}
}
