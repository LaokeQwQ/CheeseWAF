package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestUnknownTaskTypeFails(t *testing.T) {
	task := FromConfig(testSchedulerConfig("unknown"), t.TempDir(), "config.yaml", "access.log")[0]
	if err := task.Run(context.Background(), task); !errors.Is(err, ErrUnknownTaskType) {
		t.Fatalf("expected unknown task error, got %v", err)
	}
}

func TestEnginePreventsConcurrentRunsForSameTask(t *testing.T) {
	var runs atomic.Int32
	release := make(chan struct{})
	task := Task{ID: "one", Type: "cleanup", Enabled: true, Run: func(context.Context, Task) error {
		runs.Add(1)
		<-release
		return nil
	}}
	engine := NewEngine([]Task{task})
	go engine.RunNow(context.Background(), task.ID)
	time.Sleep(20 * time.Millisecond)
	engine.RunNow(context.Background(), task.ID)
	close(release)
	time.Sleep(20 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("expected one run, got %d", got)
	}
}

func TestEngineRetainsRuntimeForHotReload(t *testing.T) {
	runtime := Runtime{AIConfig: config.AIConfig{Enabled: true}}
	tasks := FromConfigWithRuntime(testSchedulerConfig("ai_self_learning"), t.TempDir(), "config.yaml", "access.log", runtime)
	engine := NewEngine(tasks)

	if got := engine.Runtime(); !got.AIConfig.Enabled {
		t.Fatal("scheduler runtime was lost after engine construction")
	}
}

func testSchedulerConfig(taskType string) config.SchedulerConfig {
	return config.SchedulerConfig{Enabled: true, Tasks: []config.ScheduledTaskConfig{{ID: "test", Type: taskType, Enabled: true}}}
}
