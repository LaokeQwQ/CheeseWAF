package monitor

import (
	"fmt"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Alert struct {
	RuleID    string    `json:"rule_id"`
	Name      string    `json:"name"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	StartsAt  time.Time `json:"starts_at"`
}

type Alerter struct {
	cfg   config.AlertEngineConfig
	mu    sync.Mutex
	state map[string]alertState
	now   func() time.Time
}

type alertState struct {
	startedAt time.Time
	lastFired time.Time
}

const defaultAlertCooldown = time.Hour

func NewAlerter(cfg config.AlertEngineConfig) *Alerter {
	return &Alerter{cfg: cfg, state: map[string]alertState{}, now: time.Now}
}

func (a *Alerter) Evaluate(snapshot Snapshot) []Alert {
	if a == nil || !a.cfg.Enabled {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	values := Values(snapshot)
	now := time.Now().UTC()
	if a.now != nil {
		now = a.now().UTC()
	}
	var alerts []Alert
	for _, rule := range a.cfg.Rules {
		if !rule.Enabled {
			continue
		}
		value, ok := values[rule.Metric]
		if !ok {
			continue
		}
		if !compare(value, rule.Operator, rule.Threshold) {
			delete(a.state, rule.ID)
			continue
		}
		state := a.state[rule.ID]
		if state.startedAt.IsZero() {
			state.startedAt = now
		}
		if rule.For > 0 && now.Sub(state.startedAt) < rule.For {
			a.state[rule.ID] = state
			continue
		}
		cooldown := rule.Cooldown
		if cooldown <= 0 {
			cooldown = defaultAlertCooldown
		}
		if !state.lastFired.IsZero() && now.Sub(state.lastFired) < cooldown {
			a.state[rule.ID] = state
			continue
		}
		state.lastFired = now
		a.state[rule.ID] = state
		alerts = append(alerts, Alert{
			RuleID:    rule.ID,
			Name:      rule.Name,
			Metric:    rule.Metric,
			Value:     value,
			Threshold: rule.Threshold,
			Severity:  empty(rule.Severity, "warning"),
			StartsAt:  state.startedAt,
			Message:   fmt.Sprintf("%s is %g %s %g", rule.Metric, value, rule.Operator, rule.Threshold),
		})
	}
	return alerts
}

func compare(value float64, op string, threshold float64) bool {
	switch op {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case "==":
		return value == threshold
	case "!=":
		return value != threshold
	default:
		return false
	}
}

func empty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
