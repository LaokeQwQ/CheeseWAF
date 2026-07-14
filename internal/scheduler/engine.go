package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Engine struct {
	mu      sync.RWMutex
	tasks   []Task
	history []HistoryEntry
	running map[string]struct{}
	parent  context.Context
	rootCtx context.Context
	cancel  context.CancelFunc
	runtime Runtime
}

var activeEngine struct {
	sync.RWMutex
	engine *Engine
}

func NewEngine(tasks []Task) *Engine {
	engine := &Engine{tasks: append([]Task(nil), tasks...), running: make(map[string]struct{})}
	if len(tasks) > 0 {
		engine.runtime = tasks[0].Runtime
	}
	return engine
}

func (e *Engine) Runtime() Runtime {
	if e == nil {
		return Runtime{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.runtime
}

func (e *Engine) Start(ctx context.Context) {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	e.parent = ctx
	e.rootCtx, e.cancel = context.WithCancel(ctx)
	tasks := append([]Task(nil), e.tasks...)
	rootCtx := e.rootCtx
	e.mu.Unlock()
	SetActive(e)
	for _, task := range tasks {
		if !task.Enabled {
			continue
		}
		task := task
		go e.loop(rootCtx, task)
	}
}

func SetActive(engine *Engine) {
	activeEngine.Lock()
	activeEngine.engine = engine
	activeEngine.Unlock()
}

func Active() *Engine {
	activeEngine.RLock()
	defer activeEngine.RUnlock()
	return activeEngine.engine
}

func (e *Engine) Replace(tasks []Task) error {
	if e == nil {
		return errors.New("scheduler engine is nil")
	}
	for _, task := range tasks {
		if !SupportedTaskType(task.Type) {
			return UnsupportedTask(context.Background(), task)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tasks = append([]Task(nil), tasks...)
	if len(tasks) > 0 {
		e.runtime = tasks[0].Runtime
	}
	if e.cancel == nil {
		return nil
	}
	e.cancel()
	if e.parent == nil || e.parent.Err() != nil {
		e.rootCtx = nil
		e.cancel = nil
		return nil
	}
	e.rootCtx, e.cancel = context.WithCancel(e.parent)
	for _, task := range e.tasks {
		if task.Enabled {
			task := task
			go e.loop(e.rootCtx, task)
		}
	}
	return nil
}

func (e *Engine) RunNow(ctx context.Context, taskID string) {
	if e == nil {
		return
	}
	e.mu.RLock()
	tasks := append([]Task(nil), e.tasks...)
	e.mu.RUnlock()
	for _, task := range tasks {
		if task.ID == taskID {
			e.run(ctx, task)
			return
		}
	}
}

func (e *Engine) Tasks() []Task {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Task, len(e.tasks))
	copy(out, e.tasks)
	return out
}

func (e *Engine) History() []HistoryEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]HistoryEntry, len(e.history))
	copy(out, e.history)
	return out
}

func (e *Engine) loop(ctx context.Context, task Task) {
	delay := task.InitialDelay
	if delay <= 0 {
		delay = task.Every
	}
	if delay <= 0 {
		delay = 24 * time.Hour
	}
	timer := time.NewTimer(delay)
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
	e.mu.Lock()
	if _, exists := e.running[task.ID]; exists {
		e.mu.Unlock()
		return
	}
	e.running[task.ID] = struct{}{}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.running, task.ID)
		e.mu.Unlock()
	}()
	start := time.Now().UTC()
	err := UnsupportedTask(ctx, task)
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
