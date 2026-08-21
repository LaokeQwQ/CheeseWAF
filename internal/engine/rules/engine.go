package rules

import (
	"context"
	"sort"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// maxPayloadBytes caps DetectionResult.Payload so long body/header matches
// cannot retain multi-KB request material in logs and alerts.
const maxPayloadBytes = 512

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

func (e *Engine) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	views := new(requestViews)
	for _, rule := range e.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !rule.Enabled {
			continue
		}
		value := views.match(rule, reqCtx)
		if rule.Pattern.MatchString(value) {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: e.ID() + "." + rule.ID,
				Category:   "custom_rule",
				Severity:   rule.Severity,
				Action:     rule.Action,
				Message:    "custom rule matched: " + rule.Name,
				Confidence: 0.8,
				Payload:    clipPayloadAroundMatch(value, rule),
			}, nil
		}
	}
	return nil, nil
}

// clipPayloadAroundMatch keeps at most maxPayloadBytes of value, preferring a
// window around the first regex match (FindStringIndex).
func clipPayloadAroundMatch(value string, rule Rule) string {
	if len(value) <= maxPayloadBytes {
		return value
	}
	matchStart, matchEnd := 0, 0
	if rule.Pattern != nil {
		if loc := rule.Pattern.FindStringIndex(value); loc != nil {
			matchStart, matchEnd = loc[0], loc[1]
		}
	}
	// Prefer ~256 bytes before the match, remainder after, clipped to budget.
	const beforeBudget = 256
	windowStart := matchStart - beforeBudget
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := windowStart + maxPayloadBytes
	if windowEnd > len(value) {
		windowEnd = len(value)
		windowStart = windowEnd - maxPayloadBytes
		if windowStart < 0 {
			windowStart = 0
		}
	}
	// Shift window if needed so a match that fits the budget is fully retained.
	if matchEnd-matchStart <= maxPayloadBytes {
		if matchStart < windowStart {
			windowStart = matchStart
			windowEnd = windowStart + maxPayloadBytes
			if windowEnd > len(value) {
				windowEnd = len(value)
				windowStart = windowEnd - maxPayloadBytes
				if windowStart < 0 {
					windowStart = 0
				}
			}
		}
		if matchEnd > windowEnd {
			windowEnd = matchEnd
			windowStart = windowEnd - maxPayloadBytes
			if windowStart < 0 {
				windowStart = 0
			}
		}
	}
	return value[windowStart:windowEnd]
}

func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}
