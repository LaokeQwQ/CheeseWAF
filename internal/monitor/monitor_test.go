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
