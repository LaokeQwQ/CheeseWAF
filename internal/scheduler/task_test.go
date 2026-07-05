package scheduler

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestFromConfigAppliesMonthlyScheduleDefaults(t *testing.T) {
	tasks := FromConfig(config.SchedulerConfig{
		Enabled: true,
		Tasks: []config.ScheduledTaskConfig{{
			ID:        "security-monthly-report",
			Type:      "security_report",
			Frequency: "monthly",
			At:        "08:00",
			Channel:   "file",
			Recipient: "./data/reports",
			Period:    "monthly",
			Enabled:   true,
		}},
	}, t.TempDir(), "config.yaml", "access.log")

	if len(tasks) != 1 {
		t.Fatalf("expected one task, got %d", len(tasks))
	}
	if tasks[0].Every != 30*24*time.Hour {
		t.Fatalf("expected monthly task every=30d, got %s", tasks[0].Every)
	}
	if tasks[0].InitialDelay <= 0 || tasks[0].InitialDelay > 24*time.Hour {
		t.Fatalf("expected monthly task to wait for next wall clock time first, got %s", tasks[0].InitialDelay)
	}
}
