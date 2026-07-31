package orchestrate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	RollingStatusPending   = "pending"
	RollingStatusRunning   = "running"
	RollingStatusSucceeded = "succeeded"
	RollingStatusFailed    = "failed"
	RollingStatusCancelled = "cancelled"

	RollingStepQueued     = "queued"
	RollingStepDraining   = "draining"
	RollingStepInstalling = "installing"
	RollingStepRestarting = "restarting"
	RollingStepHealthy    = "healthy"
	RollingStepFailed     = "failed"
	RollingStepSkipped    = "skipped"
)

// RollingTarget is one host in a rolling upgrade batch.
type RollingTarget struct {
	NodeID        string `json:"node_id,omitempty"`
	Host          string `json:"host"`
	User          string `json:"user"`
	Port          int    `json:"port,omitempty"`
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	HostKeySHA256 string `json:"host_key_sha256,omitempty"`
}

// RollingUpgradeRequest starts a sequential multi-node binary upgrade.
type RollingUpgradeRequest struct {
	Targets         []RollingTarget `json:"targets"`
	PauseBetween    string          `json:"pause_between,omitempty"`
	StopOnFailure   *bool           `json:"stop_on_failure,omitempty"`
	RestartService  *bool           `json:"restart_service,omitempty"`
	HealthURLSuffix string          `json:"health_url_suffix,omitempty"`
}

// RollingStep is one target's progress.
type RollingStep struct {
	Index     int       `json:"index"`
	NodeID    string    `json:"node_id,omitempty"`
	Host      string    `json:"host"`
	Stage     string    `json:"stage"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	TaskID    string    `json:"task_id,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RollingJob is a multi-host upgrade run.
type RollingJob struct {
	ID           string        `json:"id"`
	Status       string        `json:"status"`
	Message      string        `json:"message,omitempty"`
	Steps        []RollingStep `json:"steps"`
	StartedAt    time.Time     `json:"started_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	FinishedAt   *time.Time    `json:"finished_at,omitempty"`
	StopOnFail   bool          `json:"stop_on_failure"`
	Restart      bool          `json:"restart_service"`
	PauseBetween time.Duration `json:"-"`
}

// DeployStarter starts a single-host deploy task (install / restart).
type DeployStarter interface {
	StartInstall(ctx context.Context, target RollingTarget) (taskID string, err error)
	StartRestart(ctx context.Context, target RollingTarget) (taskID string, err error)
	WaitTask(ctx context.Context, taskID string) (ok bool, message string, err error)
}

// RollingManager runs sequential rolling upgrades.
type RollingManager struct {
	mu      sync.Mutex
	jobs    map[string]*RollingJob
	starter DeployStarter
	newID   func() string
	now     func() time.Time
}

func NewRollingManager(starter DeployStarter, newID func() string, now func() time.Time) *RollingManager {
	if newID == nil {
		newID = func() string { return fmt.Sprintf("roll-%d", time.Now().UnixNano()) }
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &RollingManager{
		jobs:    map[string]*RollingJob{},
		starter: starter,
		newID:   newID,
		now:     now,
	}
}

func (m *RollingManager) Start(ctx context.Context, req RollingUpgradeRequest) (*RollingJob, error) {
	if m == nil || m.starter == nil {
		return nil, fmt.Errorf("rolling upgrade manager is unavailable")
	}
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	for i, target := range req.Targets {
		if strings.TrimSpace(target.Host) == "" {
			return nil, fmt.Errorf("target %d host is required", i)
		}
		if strings.TrimSpace(target.User) == "" {
			return nil, fmt.Errorf("target %d user is required", i)
		}
	}
	stopOnFail := true
	if req.StopOnFailure != nil {
		stopOnFail = *req.StopOnFailure
	}
	restart := true
	if req.RestartService != nil {
		restart = *req.RestartService
	}
	pause := 3 * time.Second
	if strings.TrimSpace(req.PauseBetween) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(req.PauseBetween))
		if err != nil {
			return nil, fmt.Errorf("pause_between must be a duration such as 5s: %w", err)
		}
		if d < 0 {
			return nil, fmt.Errorf("pause_between must not be negative")
		}
		pause = d
	}
	now := m.now().UTC()
	job := &RollingJob{
		ID:           m.newID(),
		Status:       RollingStatusPending,
		StartedAt:    now,
		UpdatedAt:    now,
		StopOnFail:   stopOnFail,
		Restart:      restart,
		PauseBetween: pause,
		Steps:        make([]RollingStep, 0, len(req.Targets)),
	}
	for i, target := range req.Targets {
		job.Steps = append(job.Steps, RollingStep{
			Index:     i,
			NodeID:    strings.TrimSpace(target.NodeID),
			Host:      strings.TrimSpace(target.Host),
			Stage:     RollingStepQueued,
			Status:    RollingStatusPending,
			UpdatedAt: now,
		})
	}
	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()

	go m.run(context.Background(), job.ID, req.Targets)
	return m.Get(job.ID)
}

func (m *RollingManager) Get(id string) (*RollingJob, error) {
	if m == nil {
		return nil, fmt.Errorf("rolling upgrade manager is unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("rolling upgrade job not found")
	}
	copyJob := *job
	copyJob.Steps = append([]RollingStep(nil), job.Steps...)
	return &copyJob, nil
}

func (m *RollingManager) List() []RollingJob {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RollingJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		copyJob := *job
		copyJob.Steps = append([]RollingStep(nil), job.Steps...)
		out = append(out, copyJob)
	}
	return out
}

func (m *RollingManager) run(ctx context.Context, jobID string, targets []RollingTarget) {
	m.updateJob(jobID, func(job *RollingJob) {
		job.Status = RollingStatusRunning
		job.Message = "rolling upgrade in progress"
		job.UpdatedAt = m.now().UTC()
	})
	for i, target := range targets {
		if ctx.Err() != nil {
			m.failJob(jobID, "rolling upgrade cancelled")
			return
		}
		m.updateStep(jobID, i, RollingStepInstalling, RollingStatusRunning, "uploading and installing binary", "")
		taskID, err := m.starter.StartInstall(ctx, target)
		if err != nil {
			m.updateStep(jobID, i, RollingStepFailed, RollingStatusFailed, err.Error(), taskID)
			if m.shouldStop(jobID) {
				m.failJob(jobID, fmt.Sprintf("install failed on %s: %v", target.Host, err))
				return
			}
			continue
		}
		ok, message, err := m.starter.WaitTask(ctx, taskID)
		if err != nil || !ok {
			if message == "" && err != nil {
				message = err.Error()
			}
			if message == "" {
				message = "install task failed"
			}
			m.updateStep(jobID, i, RollingStepFailed, RollingStatusFailed, message, taskID)
			if m.shouldStop(jobID) {
				m.failJob(jobID, fmt.Sprintf("install failed on %s: %s", target.Host, message))
				return
			}
			continue
		}
		job, _ := m.Get(jobID)
		if job != nil && job.Restart {
			m.updateStep(jobID, i, RollingStepRestarting, RollingStatusRunning, "restarting service", taskID)
			restartID, err := m.starter.StartRestart(ctx, target)
			if err != nil {
				m.updateStep(jobID, i, RollingStepFailed, RollingStatusFailed, err.Error(), restartID)
				if m.shouldStop(jobID) {
					m.failJob(jobID, fmt.Sprintf("restart failed on %s: %v", target.Host, err))
					return
				}
				continue
			}
			ok, message, err = m.starter.WaitTask(ctx, restartID)
			if err != nil || !ok {
				if message == "" && err != nil {
					message = err.Error()
				}
				if message == "" {
					message = "restart task failed"
				}
				m.updateStep(jobID, i, RollingStepFailed, RollingStatusFailed, message, restartID)
				if m.shouldStop(jobID) {
					m.failJob(jobID, fmt.Sprintf("restart failed on %s: %s", target.Host, message))
					return
				}
				continue
			}
			taskID = restartID
		}
		m.updateStep(jobID, i, RollingStepHealthy, RollingStatusSucceeded, "node upgrade complete", taskID)
		if i < len(targets)-1 {
			if job, _ := m.Get(jobID); job != nil && job.PauseBetween > 0 {
				timer := time.NewTimer(job.PauseBetween)
				select {
				case <-ctx.Done():
					timer.Stop()
					m.failJob(jobID, "rolling upgrade cancelled during pause")
					return
				case <-timer.C:
				}
			}
		}
	}
	m.updateJob(jobID, func(job *RollingJob) {
		now := m.now().UTC()
		job.Status = RollingStatusSucceeded
		job.Message = "rolling upgrade completed"
		job.UpdatedAt = now
		job.FinishedAt = &now
	})
}

func (m *RollingManager) shouldStop(jobID string) bool {
	job, err := m.Get(jobID)
	if err != nil || job == nil {
		return true
	}
	return job.StopOnFail
}

func (m *RollingManager) failJob(jobID, message string) {
	m.updateJob(jobID, func(job *RollingJob) {
		now := m.now().UTC()
		job.Status = RollingStatusFailed
		job.Message = message
		job.UpdatedAt = now
		job.FinishedAt = &now
	})
}

func (m *RollingManager) updateJob(jobID string, fn func(*RollingJob)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[jobID]
	if !ok {
		return
	}
	fn(job)
}

func (m *RollingManager) updateStep(jobID string, index int, stage, status, message, taskID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[jobID]
	if !ok || index < 0 || index >= len(job.Steps) {
		return
	}
	job.Steps[index].Stage = stage
	job.Steps[index].Status = status
	job.Steps[index].Message = message
	if taskID != "" {
		job.Steps[index].TaskID = taskID
	}
	job.Steps[index].UpdatedAt = m.now().UTC()
	job.UpdatedAt = job.Steps[index].UpdatedAt
}
