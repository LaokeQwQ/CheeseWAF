package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"
)

type engineGeneration struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type Engine struct {
	lifecycleMu sync.Mutex
	mu          sync.RWMutex
	tasks       []Task
	history     []HistoryEntry
	running     map[string]struct{}
	parent      context.Context
	generation  *engineGeneration
	runtime     Runtime
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
	if ctx == nil {
		ctx = context.Background()
	}
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.stopGeneration()

	e.mu.RLock()
	tasks := append([]Task(nil), e.tasks...)
	e.mu.RUnlock()
	e.launchGeneration(ctx, tasks)
	SetActive(e)
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

	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.mu.Lock()
	e.tasks = append([]Task(nil), tasks...)
	if len(tasks) > 0 {
		e.runtime = tasks[0].Runtime
	}
	parent := e.parent
	started := e.generation != nil
	e.mu.Unlock()
	if !started {
		return nil
	}

	e.stopGeneration()
	if parent == nil || parent.Err() != nil {
		return nil
	}
	e.launchGeneration(parent, tasks)
	return nil
}

func (e *Engine) stopGeneration() {
	e.mu.Lock()
	old := e.generation
	e.generation = nil
	e.mu.Unlock()
	if old == nil {
		return
	}
	old.cancel()
	old.wg.Wait()
}

func (e *Engine) launchGeneration(parent context.Context, tasks []Task) {
	ctx, cancel := context.WithCancel(parent)
	generation := &engineGeneration{ctx: ctx, cancel: cancel}
	enabled := make([]Task, 0, len(tasks))
	for _, task := range tasks {
		if task.Enabled {
			enabled = append(enabled, task)
		}
	}
	generation.wg.Add(len(enabled))
	e.mu.Lock()
	e.parent = parent
	e.generation = generation
	e.mu.Unlock()
	for _, task := range enabled {
		task := task
		go func() {
			defer generation.wg.Done()
			e.loop(generation.ctx, task)
		}()
	}
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
	interval := task.Every
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.run(ctx, task)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(interval)
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
