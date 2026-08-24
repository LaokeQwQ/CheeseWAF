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

	// Rolling job retention: jobs expire after 7 days to prevent unbounded memory growth
	rollingJobTTL = 7 * 24 * time.Hour
	// Maximum jobs retained: oldest jobs are pruned when limit is reached
	maxRollingJobs = 500
)

// RollingTarget is one host in a rolling upgrade batch.
type RollingTarget struct {
	NodeID        string   `json:"node_id,omitempty"`
	Host          string   `json:"host"`
	User          string   `json:"user"`
	Port          int      `json:"port,omitempty"`
	Password      string   `json:"password,omitempty"`
	PrivateKey    string   `json:"private_key,omitempty"`
	HostKeySHA256 string   `json:"host_key_sha256,omitempty"`
	ResolvedIPs   []string `json:"-"`
}

// RollingUpgradeRequest starts a sequential multi-node binary upgrade.
type RollingUpgradeRequest struct {
	Targets        []RollingTarget `json:"targets"`
	PauseBetween   string          `json:"pause_between,omitempty"`
	StopOnFailure  *bool           `json:"stop_on_failure,omitempty"`
	RestartService *bool           `json:"restart_service,omitempty"`
	// AutoRollback reinstalls previously succeeded targets in reverse order when a step fails.
	AutoRollback *bool `json:"auto_rollback,omitempty"`
	// InitiatedBy records the user/token that created this job (for audit and rollback authorization)
	InitiatedBy string `json:"initiated_by,omitempty"`
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
	AutoRollback bool          `json:"auto_rollback"`
	// RollbackOf links a reverse-order restore job to the failed upgrade it repairs.
	RollbackOf string `json:"rollback_of,omitempty"`
	// RollbackJobID is filled when auto-rollback starts a follow-up job.
	RollbackJobID string `json:"rollback_job_id,omitempty"`
	// DeployAction is install for upgrades and rollback-install for backup restore.
	DeployAction string        `json:"deploy_action,omitempty"`
	PauseBetween time.Duration `json:"-"`
	// targets retains credentials for rollback; never serialized to clients.
	targets []RollingTarget `json:"-"`
	// CreatedAt records when the job was created for TTL enforcement
	CreatedAt time.Time `json:"created_at"`
	// InitiatedBy records the user/token that created this job (for rollback authorization)
	InitiatedBy string `json:"initiated_by,omitempty"`
}

// DeployStarter starts a single-host deploy task (install / rollback / restart).
type DeployStarter interface {
	StartInstall(ctx context.Context, target RollingTarget) (taskID string, err error)
	// StartRollbackInstall restores the newest remote binary backup (rollback-install).
	StartRollbackInstall(ctx context.Context, target RollingTarget) (taskID string, err error)
	StartRestart(ctx context.Context, target RollingTarget) (taskID string, err error)
	WaitTask(ctx context.Context, taskID string) (ok bool, message string, err error)
}

const (
	rollingActionInstall         = "install"
	rollingActionRollbackInstall = "rollback-install"
)

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
	autoRollback := false
	if req.AutoRollback != nil {
		autoRollback = *req.AutoRollback
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
	targetsCopy := append([]RollingTarget(nil), req.Targets...)
	job := &RollingJob{
		ID:           m.newID(),
		Status:       RollingStatusPending,
		StartedAt:    now,
		UpdatedAt:    now,
		CreatedAt:    now,
		InitiatedBy:  req.InitiatedBy,
		StopOnFail:   stopOnFail,
		Restart:      restart,
		AutoRollback: autoRollback,
		DeployAction: rollingActionInstall,
		PauseBetween: pause,
		Steps:        make([]RollingStep, 0, len(req.Targets)),
		targets:      targetsCopy,
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
	m.pruneExpiredJobsLocked()
	if len(m.jobs) >= maxRollingJobs {
		m.pruneOldestJobsLocked()
	}
	m.jobs[job.ID] = job
	m.mu.Unlock()

	go m.run(context.Background(), job.ID, targetsCopy)
	return m.Get(job.ID)
}

// StartRollback restores previously succeeded hosts from a finished job in reverse order.
// Each host uses rollback-install (the exact previous generation), not a fresh install of the new binary.
func (m *RollingManager) StartRollback(ctx context.Context, jobID string) (*RollingJob, error) {
	if m == nil {
		return nil, fmt.Errorf("rolling upgrade manager is unavailable")
	}
	src, err := m.Get(jobID)
	if err != nil {
		return nil, err
	}
	if src.Status == RollingStatusPending || src.Status == RollingStatusRunning {
		return nil, fmt.Errorf("cannot roll back a job that is still running")
	}
	if strings.TrimSpace(src.RollbackJobID) != "" {
		return m.Get(src.RollbackJobID)
	}
	if src.DeployAction == rollingActionRollbackInstall || strings.TrimSpace(src.RollbackOf) != "" {
		return nil, fmt.Errorf("cannot roll back a rollback job")
	}
	m.mu.Lock()
	stored, ok := m.jobs[strings.TrimSpace(jobID)]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("rolling upgrade job not found")
	}
	if strings.TrimSpace(stored.RollbackJobID) != "" {
		existing := stored.RollbackJobID
		m.mu.Unlock()
		return m.Get(existing)
	}
	targets := append([]RollingTarget(nil), stored.targets...)
	pause := stored.PauseBetween
	restart := stored.Restart
	// Reserve the rollback slot before spawning so concurrent calls do not double-start.
	placeholderID := m.newID()
	stored.RollbackJobID = placeholderID
	m.mu.Unlock()

	reversed := reverseSucceededTargets(src.Steps, targets)
	if len(reversed) == 0 {
		m.updateJob(src.ID, func(j *RollingJob) {
			if j.RollbackJobID == placeholderID {
				j.RollbackJobID = ""
			}
		})
		return nil, fmt.Errorf("no succeeded targets available to roll back")
	}
	stop := true
	auto := false
	pauseStr := ""
	if pause > 0 {
		pauseStr = pause.String()
	}
	// Build rollback job with reserved id and rollback-install action.
	now := m.now().UTC()
	job := &RollingJob{
		ID:           placeholderID,
		Status:       RollingStatusPending,
		StartedAt:    now,
		UpdatedAt:    now,
		CreatedAt:    now,
		InitiatedBy:  stored.InitiatedBy,
		StopOnFail:   stop,
		Restart:      restart,
		AutoRollback: auto,
		DeployAction: rollingActionRollbackInstall,
		RollbackOf:   src.ID,
		Message:      fmt.Sprintf("rollback of %s (restore remote backups)", src.ID),
		PauseBetween: pause,
		Steps:        make([]RollingStep, 0, len(reversed)),
		targets:      append([]RollingTarget(nil), reversed...),
	}
	for i, target := range reversed {
		job.Steps = append(job.Steps, RollingStep{
			Index:     i,
			NodeID:    strings.TrimSpace(target.NodeID),
			Host:      strings.TrimSpace(target.Host),
			Stage:     RollingStepQueued,
			Status:    RollingStatusPending,
			UpdatedAt: now,
		})
	}
	_ = pauseStr // pause already applied on job
	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()
	go m.run(context.Background(), job.ID, reversed)
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
		action := m.deployAction(jobID)
		stageLabel := "uploading and installing binary"
		if action == rollingActionRollbackInstall {
			stageLabel = "restoring newest binary backup"
		}
		m.updateStep(jobID, i, RollingStepInstalling, RollingStatusRunning, stageLabel, "")
		taskID, err := m.startDeploy(ctx, action, target)
		if err != nil {
			m.updateStep(jobID, i, RollingStepFailed, RollingStatusFailed, err.Error(), taskID)
			if m.shouldStop(jobID) {
				m.failJob(jobID, fmt.Sprintf("%s failed on %s: %v", action, target.Host, err))
				m.maybeAutoRollback(jobID)
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
				message = action + " task failed"
			}
			m.updateStep(jobID, i, RollingStepFailed, RollingStatusFailed, message, taskID)
			if m.shouldStop(jobID) {
				m.failJob(jobID, fmt.Sprintf("%s failed on %s: %s", action, target.Host, message))
				m.maybeAutoRollback(jobID)
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
					m.maybeAutoRollback(jobID)
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
					m.maybeAutoRollback(jobID)
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
		// Keep the source job's credentials until its rollback window expires.
		// A rollback job itself no longer needs them after successful completion.
		if job.RollbackOf != "" {
			clearRollingTargetCredentialsLocked(job)
			if source, ok := m.jobs[job.RollbackOf]; ok {
				clearRollingTargetCredentialsLocked(source)
			}
		}
	})
}

func (m *RollingManager) shouldStop(jobID string) bool {
	job, err := m.Get(jobID)
	if err != nil || job == nil {
		return true
	}
	return job.StopOnFail
}

func (m *RollingManager) deployAction(jobID string) string {
	job, err := m.Get(jobID)
	if err != nil || job == nil || strings.TrimSpace(job.DeployAction) == "" {
		return rollingActionInstall
	}
	return job.DeployAction
}

func (m *RollingManager) startDeploy(ctx context.Context, action string, target RollingTarget) (string, error) {
	if action == rollingActionRollbackInstall {
		return m.starter.StartRollbackInstall(ctx, target)
	}
	return m.starter.StartInstall(ctx, target)
}

func (m *RollingManager) maybeAutoRollback(jobID string) {
	job, err := m.Get(jobID)
	if err != nil || job == nil || !job.AutoRollback || job.RollbackOf != "" {
		// Never auto-chain rollbacks of rollbacks.
		return
	}
	if job.Status != RollingStatusFailed {
		return
	}
	hasSucceeded := false
	for _, step := range job.Steps {
		if step.Status == RollingStatusSucceeded {
			hasSucceeded = true
			break
		}
	}
	if !hasSucceeded {
		return
	}
	rollback, err := m.StartRollback(context.Background(), jobID)
	if err != nil {
		m.updateJob(jobID, func(j *RollingJob) {
			if j.Message == "" {
				j.Message = err.Error()
			} else {
				j.Message = j.Message + "; auto-rollback failed: " + err.Error()
			}
			j.UpdatedAt = m.now().UTC()
		})
		return
	}
	m.updateJob(jobID, func(j *RollingJob) {
		j.RollbackJobID = rollback.ID
		j.Message = j.Message + "; auto-rollback started as " + rollback.ID
		j.UpdatedAt = m.now().UTC()
	})
}

func reverseSucceededTargets(steps []RollingStep, targets []RollingTarget) []RollingTarget {
	byHost := map[string]RollingTarget{}
	for _, target := range targets {
		byHost[strings.TrimSpace(target.Host)] = target
	}
	out := make([]RollingTarget, 0, len(steps))
	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if step.Status != RollingStatusSucceeded {
			continue
		}
		if target, ok := byHost[strings.TrimSpace(step.Host)]; ok {
			out = append(out, target)
			continue
		}
		out = append(out, RollingTarget{
			NodeID: step.NodeID,
			Host:   step.Host,
		})
	}
	return out
}

func (m *RollingManager) failJob(jobID, message string) {
	m.updateJob(jobID, func(job *RollingJob) {
		now := m.now().UTC()
		job.Status = RollingStatusFailed
		job.Message = message
		job.UpdatedAt = now
		job.FinishedAt = &now
		// A failed rollback may be retried while the source job is retained, so
		// keep the source credentials but discard the failed rollback copy.
		if job.RollbackOf != "" {
			clearRollingTargetCredentialsLocked(job)
		}
	})
}

func clearRollingTargetCredentialsLocked(job *RollingJob) {
	if job == nil {
		return
	}
	for i := range job.targets {
		job.targets[i].Password = ""
		job.targets[i].PrivateKey = ""
	}
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
