// Package scheduler runs lightweight operational jobs.
package scheduler

import (
	"context"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type TaskFunc func(context.Context, Task) error

type Task struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Schedule  string        `json:"schedule"`
	Every     time.Duration `json:"every"`
	Target    string        `json:"target"`
	Keep      int           `json:"keep"`
	Enabled   bool          `json:"enabled"`
	CreatedAt time.Time     `json:"created_at"`
	Run       TaskFunc      `json:"-"`
}

type HistoryEntry struct {
	TaskID    string        `json:"task_id"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}

func FromConfig(cfg config.SchedulerConfig, dataDir, configPath string) []Task {
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
			Target:    item.Target,
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
		if task.Every <= 0 {
			task.Every = 24 * time.Hour
		}
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
		default:
			task.Run = Noop
		}
		tasks = append(tasks, task)
	}
	return tasks
}

func Noop(context.Context, Task) error { return nil }
