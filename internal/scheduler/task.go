// Package scheduler runs lightweight operational jobs.
package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type TaskFunc func(context.Context, Task) error

type Task struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Type         string        `json:"type"`
	Schedule     string        `json:"schedule"`
	Every        time.Duration `json:"every"`
	Frequency    string        `json:"frequency"`
	At           string        `json:"at"`
	Target       string        `json:"target"`
	Channel      string        `json:"channel"`
	Recipient    string        `json:"recipient"`
	Period       string        `json:"period"`
	Format       string        `json:"format"`
	Keep         int           `json:"keep"`
	Enabled      bool          `json:"enabled"`
	CreatedAt    time.Time     `json:"created_at"`
	Run          TaskFunc      `json:"-"`
	InitialDelay time.Duration `json:"-"`
}

type HistoryEntry struct {
	TaskID    string        `json:"task_id"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}

func FromConfig(cfg config.SchedulerConfig, dataDir, configPath, logPath string) []Task {
	return FromConfigWithRuntime(cfg, dataDir, configPath, logPath, Runtime{})
}

type Runtime struct {
	AIConfig config.AIConfig
	Sink     storage.LogSink
	Store    storage.RuleStore
	Client   *ai.Client
}

func FromConfigWithRuntime(cfg config.SchedulerConfig, dataDir, configPath, logPath string, runtime Runtime) []Task {
	if !cfg.Enabled {
		return nil
	}
	tasks := make([]Task, 0, len(cfg.Tasks))
	for _, item := range cfg.Tasks {
		task := Task{
			ID:        item.ID,
			Name:      item.Name,
			Type:      item.Type,
			Schedule:  item.Schedule,
			Every:     item.Every,
			Frequency: item.Frequency,
			At:        item.At,
			Target:    item.Target,
			Channel:   item.Channel,
			Recipient: item.Recipient,
			Period:    item.Period,
			Format:    item.Format,
			Keep:      item.Keep,
			Enabled:   item.Enabled,
			CreatedAt: item.CreatedAt,
		}
		if task.ID == "" {
			task.ID = task.Type + "-" + task.Target
		}
		if task.Name == "" {
			task.Name = task.ID
		}
		applyScheduleDefaults(&task)
		if task.Keep <= 0 {
			task.Keep = 7
		}
		if task.CreatedAt.IsZero() {
			task.CreatedAt = time.Now().UTC()
		}
		switch task.Type {
		case "backup":
			task.Run = BackupConfig(configPath, dataDir)
		case "cleanup":
			task.Run = CleanupOldFiles
		case "security_report":
			task.Run = SecurityReport(logPath, dataDir)
		case "ai_self_learning", "self_learning_rules":
			task.Run = AISelfLearning(runtime)
		default:
			task.Run = Noop
		}
		tasks = append(tasks, task)
	}
	return tasks
}

func Noop(context.Context, Task) error { return nil }

func applyScheduleDefaults(task *Task) {
	if task.Frequency == "" && task.Schedule != "" {
		task.Frequency = task.Schedule
	}
	if task.Frequency == "" {
		task.Frequency = "interval"
	}
	if task.At == "" {
		task.At = "08:00"
	}
	switch task.Frequency {
	case "daily":
		task.Every = 24 * time.Hour
		task.InitialDelay = nextWallClockDelay(task.At, time.Now)
	case "weekly":
		task.Every = 7 * 24 * time.Hour
		task.InitialDelay = nextWallClockDelay(task.At, time.Now)
	default:
		if task.Every <= 0 {
			task.Every = 24 * time.Hour
		}
		task.InitialDelay = task.Every
	}
}

func nextWallClockDelay(at string, nowFn func() time.Time) time.Duration {
	now := nowFn()
	hour, minute := 8, 0
	_, _ = fmt.Sscanf(at, "%d:%d", &hour, &minute)
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}
