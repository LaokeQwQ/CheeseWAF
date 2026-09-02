package rules

import (
	"context"
	"sort"
	"strings"

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
	var best *engine.DetectionResult
	for _, rule := range e.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !rule.Enabled {
			continue
		}
		value := views.match(rule, reqCtx)
		if rule.literalPrefix != "" && !strings.Contains(value, rule.literalPrefix) {
			continue
		}
		if rule.Pattern.MatchString(value) {
			result := &engine.DetectionResult{
				Detected:   true,
				DetectorID: e.ID() + "." + rule.ID,
				Category:   "custom_rule",
				Severity:   rule.Severity,
				Action:     rule.Action,
				Message:    "custom rule matched: " + rule.Name,
				Confidence: 0.8,
				Payload:    matchPayload(value, rule),
			}
			if best == nil || actionStrength(result.Action) > actionStrength(best.Action) {
				best = result
			}
		}
	}
	return best, nil
}

func matchPayload(value string, rule Rule) string {
	switch rule.Location {
	case "header":
		return "[redacted header match]"
	case "cookie":
		return "[redacted cookie match]"
	default:
		return clipPayloadAroundMatch(value, rule)
	}
}

func actionStrength(action engine.Action) int {
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
