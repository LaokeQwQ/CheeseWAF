package ip

import (
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Indicator struct {
	ID         string    `json:"id"`
	Value      string    `json:"value"`
	Type       string    `json:"type"`
	Severity   string    `json:"severity"`
	Source     string    `json:"source"`
	Labels     []string  `json:"labels"`
	Action     string    `json:"action"`
	Confidence float64   `json:"confidence"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

type ThreatDecision struct {
	Matched           bool        `json:"matched"`
	Level             string      `json:"level"`
	Action            string      `json:"action"`
	Reason            string      `json:"reason"`
	Severity          string      `json:"severity"`
	Confidence        float64     `json:"confidence"`
	Score             int         `json:"score"`
	MinimumScore      int         `json:"minimum_score"`
	DetectorID        string      `json:"detector_id"`
	Message           string      `json:"message"`
	Indicators        []Indicator `json:"indicators"`
	SourceCount       int         `json:"source_count"`
	RecommendedAction string      `json:"recommended_action"`
}

type Intel struct {
	items []indicatorMatcher
	now   func() time.Time
}

type indicatorMatcher struct {
	indicator Indicator
	ip        net.IP
	network   *net.IPNet
}

func NewIntel(configs []config.ThreatIntelConfig) (*Intel, error) {
	intel := &Intel{now: time.Now}
	for _, item := range configs {
		if !item.Enabled || strings.TrimSpace(item.Value) == "" {
			continue
		}
		matcher := indicatorMatcher{
			indicator: Indicator{
				ID:         item.ID,
				Value:      strings.TrimSpace(item.Value),
				Type:       empty(item.Type, "ip"),
				Severity:   strings.ToLower(empty(item.Severity, "medium")),
				Source:     item.Source,
				Labels:     cloneStrings(item.Labels),
				Action:     normalizeIndicatorAction(item.Action),
				Confidence: normalizeConfidence(item.Confidence),
				ExpiresAt:  item.ExpiresAt,
			},
		}
		if strings.Contains(item.Value, "/") {
			_, network, err := net.ParseCIDR(item.Value)
			if err != nil {
				return nil, err
			}
			matcher.network = network
		} else if parsed := net.ParseIP(item.Value); parsed != nil {
			matcher.ip = parsed
		}
		intel.items = append(intel.items, matcher)
	}
	return intel, nil
}

func (i *Intel) Match(raw string) []Indicator {
	if i == nil {
		return []Indicator{}
	}
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil {
		return []Indicator{}
	}
	out := make([]Indicator, 0)
	now := i.now().UTC()
	for _, item := range i.items {
		if !item.indicator.ExpiresAt.IsZero() && item.indicator.ExpiresAt.Before(now) {
			continue
		}
		if item.ip != nil && item.ip.Equal(parsed) {
			out = append(out, item.indicator)
			continue
		}
		if item.network != nil && item.network.Contains(parsed) {
			out = append(out, item.indicator)
		}
	}
	return out
}

func (i *Intel) Values() []Indicator {
	if i == nil {
		return []Indicator{}
	}
	out := make([]Indicator, 0, len(i.items))
	now := i.now().UTC()
	for _, item := range i.items {
		if !item.indicator.ExpiresAt.IsZero() && item.indicator.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, item.indicator)
	}
	return out
}

func (i *Intel) Evaluate(raw, level string) ThreatDecision {
	if level == "" {
		level = config.ProtectionLevelSmart
	}
	threshold := threatIntelThreshold(level)
	decision := ThreatDecision{
		Level:        level,
		Action:       "pass",
		Reason:       "no threat intelligence match",
		MinimumScore: threshold,
		DetectorID:   "ip.threat_intel",
	}
	if level == config.ProtectionLevelOff {
		decision.Reason = "threat intelligence protection disabled"
		return decision
	}
	matches := i.Match(raw)
	if len(matches) == 0 {
		return decision
	}
	score, severity, confidence, action, sources := scoreIndicators(matches)
	decision.Matched = true
	decision.Action = "log"
	decision.Reason = "threat intelligence matched below policy threshold"
	decision.Severity = severity
	decision.Confidence = confidence
	decision.Score = score
	decision.Indicators = matches
	decision.SourceCount = sources
	decision.RecommendedAction = action
	decision.Message = threatIntelMessage(matches, score)
	if score >= threshold {
		decision.Action = action
		decision.Reason = "threat intelligence score meets policy threshold"
	}
	return decision
}

func threatIntelThreshold(level string) int {
	switch level {
	case config.ProtectionLevelLow:
		return 92
	case config.ProtectionLevelHigh:
		return 62
	case config.ProtectionLevelStrict:
		return 45
	default:
		return 75
	}
}

func scoreIndicators(matches []Indicator) (int, string, float64, string, int) {
	bestScore := 0
	bestSeverity := "low"
	bestConfidence := 0.0
	action := "log"
	sources := map[string]struct{}{}
	for _, indicator := range matches {
		confidence := indicator.Confidence
		if confidence <= 0 {
			confidence = defaultConfidence(indicator.Severity)
		}
		severityScore := severityScore(indicator.Severity)
		score := int(math.Round(float64(severityScore) * confidence))
		if score > bestScore {
			bestScore = score
			bestSeverity = normalizeSeverityName(indicator.Severity)
			bestConfidence = confidence
		}
		action = strongerAction(action, indicator.Action)
		if source := strings.TrimSpace(indicator.Source); source != "" {
			sources[source] = struct{}{}
		}
	}
	if len(matches) > 1 {
		bestScore += minInt((len(matches)-1)*5, 15)
	}
	if len(sources) > 1 {
		bestScore += minInt((len(sources)-1)*8, 16)
	}
	if bestScore > 100 {
		bestScore = 100
	}
	if action == "" {
		action = "challenge"
	}
	return bestScore, bestSeverity, bestConfidence, action, len(sources)
}

func severityScore(severity string) int {
	switch normalizeSeverityName(severity) {
	case "critical":
		return 100
	case "high":
		return 86
	case "medium":
		return 62
	default:
		return 35
	}
}

func defaultConfidence(severity string) float64 {
	switch normalizeSeverityName(severity) {
	case "critical":
		return 0.95
	case "high":
		return 0.86
	case "medium":
		return 0.72
	default:
		return 0.55
	}
}

func normalizeSeverityName(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return "medium"
	}
}

func normalizeIndicatorAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "challenge", "log":
		return strings.ToLower(strings.TrimSpace(action))
	default:
		return "challenge"
	}
}

func normalizeConfidence(confidence float64) float64 {
	if confidence > 1 {
		confidence = confidence / 100
	}
	if confidence < 0 {
		return 0
	}
	if confidence > 1 {
		return 1
	}
	return confidence
}

func strongerAction(current, next string) string {
	order := map[string]int{"log": 1, "challenge": 2, "block": 3}
	next = normalizeIndicatorAction(next)
	if order[next] > order[current] {
		return next
	}
	return current
}

func threatIntelMessage(matches []Indicator, score int) string {
	if len(matches) == 0 {
		return "threat intelligence matched"
	}
	first := matches[0]
	source := strings.TrimSpace(first.Source)
	if source == "" {
		source = "local"
	}
	return "IP matched threat intelligence from " + source + " with score " + strconv.Itoa(score)
}

func empty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
