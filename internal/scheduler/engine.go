package scheduler

import (
	"context"
	"sync"
	"time"
)

type Engine struct {
	mu      sync.Mutex
	tasks   []Task
	history []HistoryEntry
}

func NewEngine(tasks []Task) *Engine {
	return &Engine{tasks: tasks}
}

func (e *Engine) Start(ctx context.Context) {
	if e == nil {
		return
	}
	for _, task := range e.tasks {
		if !task.Enabled {
			continue
		}
		task := task
		go e.loop(ctx, task)
	}
}

func (e *Engine) RunNow(ctx context.Context, taskID string) {
	if e == nil {
		return
	}
	for _, task := range e.tasks {
		if task.ID == taskID {
			e.run(ctx, task)
			return
		}
	}
}

func (e *Engine) Tasks() []Task {
	out := make([]Task, len(e.tasks))
	copy(out, e.tasks)
	return out
}

func (e *Engine) History() []HistoryEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]HistoryEntry, len(e.history))
	copy(out, e.history)
	return out
}

func (e *Engine) loop(ctx context.Context, task Task) {
	timer := time.NewTimer(task.Every)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.run(ctx, task)
			timer.Reset(task.Every)
		}
	}
}

func (e *Engine) run(ctx context.Context, task Task) {
	start := time.Now().UTC()
	err := Noop(ctx, task)
	if task.Run != nil {
		err = task.Run(ctx, task)
	}
	entry := HistoryEntry{
		TaskID:    task.ID,
		StartedAt: start,
		Duration:  time.Since(start),
		Success:   err == nil,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	e.mu.Lock()
	e.history = append([]HistoryEntry{entry}, e.history...)
	if len(e.history) > 100 {
		e.history = e.history[:100]
	}
	e.mu.Unlock()
}
