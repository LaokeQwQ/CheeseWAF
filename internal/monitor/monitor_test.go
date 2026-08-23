package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestRenderPrometheusIncludesCoreMetrics(t *testing.T) {
	snapshot := Collect(time.Now().Add(-time.Minute), 2, []storage.LogEntry{
		{Action: "block", StatusCode: 403, Category: "sqli"},
	}, map[string]int64{"data": 42})
	out := string(RenderPrometheus(snapshot))
	if !strings.Contains(out, "cheesewaf_blocked_total 1") || !strings.Contains(out, `category="sqli"`) {
		t.Fatalf("unexpected prometheus output:\n%s", out)
	}
	if snapshot.ProcessCount <= 0 || !strings.Contains(out, "cheesewaf_process_count") {
		t.Fatalf("expected process count metric, snapshot=%+v output:\n%s", snapshot, out)
	}
}

func TestAlerterFiresRule(t *testing.T) {
	alerter := NewAlerter(config.AlertEngineConfig{
		Enabled: true,
		Rules: []config.AlertRuleConfig{
			{ID: "blocked", Name: "Blocked", Metric: "cheesewaf_blocked_total", Operator: ">", Threshold: 0, Enabled: true},
		},
	})
	alerts := alerter.Evaluate(Snapshot{Blocked: 1})
	if len(alerts) != 1 || alerts[0].RuleID != "blocked" {
		t.Fatalf("expected blocked alert, got %+v", alerts)
	}
}

func TestAlerterDeduplicatesDuringCooldownAndResetsAfterRecovery(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	alerter := NewAlerter(config.AlertEngineConfig{
		Enabled: true,
		Rules: []config.AlertRuleConfig{{
			ID: "cpu", Metric: "cheesewaf_blocked_total", Operator: ">", Threshold: 0,
			Cooldown: 10 * time.Minute, Enabled: true,
		}},
	})
	alerter.now = func() time.Time { return now }
	if got := len(alerter.Evaluate(Snapshot{Blocked: 1})); got != 1 {
		t.Fatalf("first alert count = %d, want 1", got)
	}
	now = now.Add(time.Minute)
	if got := len(alerter.Evaluate(Snapshot{Blocked: 1})); got != 0 {
		t.Fatalf("alert repeated inside cooldown: %d", got)
	}
	now = now.Add(10 * time.Minute)
	if got := len(alerter.Evaluate(Snapshot{Blocked: 1})); got != 1 {
		t.Fatalf("alert did not re-fire after cooldown: %d", got)
	}
	if got := len(alerter.Evaluate(Snapshot{Blocked: 0})); got != 0 {
		t.Fatalf("recovery emitted an alert: %d", got)
	}
	now = now.Add(time.Second)
	if got := len(alerter.Evaluate(Snapshot{Blocked: 1})); got != 1 {
		t.Fatalf("alert did not fire as a new incident after recovery: %d", got)
	}
}

func TestAlerterStateIsSafeForConcurrentEvaluation(t *testing.T) {
	alerter := NewAlerter(config.AlertEngineConfig{
		Enabled: true,
		Rules:   []config.AlertRuleConfig{{ID: "blocked", Metric: "cheesewaf_blocked_total", Operator: ">", Threshold: 0, Enabled: true}},
	})
	alerter.now = func() time.Time { return time.Now().UTC() }
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = alerter.Evaluate(Snapshot{Blocked: 1})
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
