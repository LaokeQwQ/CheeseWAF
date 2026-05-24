package rules

import (
	"context"
	"sort"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type Engine struct {
	rules []Rule
}

func New(ruleSet []Rule) *Engine {
	out := append([]Rule(nil), ruleSet...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority < out[j].Priority
	})
	return &Engine{rules: out}
}

func (e *Engine) ID() string    { return "rules.custom" }
func (e *Engine) Name() string  { return "Custom Rule Engine" }
func (e *Engine) Priority() int { return 250 }

func (e *Engine) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		value := MatchValue(rule, reqCtx)
		if rule.Pattern.MatchString(value) {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: e.ID() + "." + rule.ID,
				Category:   "custom_rule",
				Severity:   rule.Severity,
				Action:     rule.Action,
				Message:    "custom rule matched: " + rule.Name,
				Confidence: 0.8,
				Payload:    value,
			}, nil
		}
	}
	return nil, nil
}

func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}
