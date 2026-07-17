package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	TaskStatusPending   = "pending"
	TaskStatusRunning   = "running"
	TaskStatusSucceeded = "succeeded"
	TaskStatusFailed    = "failed"
	TaskStatusCancelled = "cancelled"

	TaskEventQueued                    = "queued"
	TaskEventValidating                = "validating"
	TaskEventConnecting                = "connecting"
	TaskEventChecked                   = "checked"
	TaskEventDeployed                  = "deployed"
	TaskEventFailed                    = "failed"
	TaskEventCompensating              = "compensating"
	TaskEventCompensated               = "compensated"
	TaskEventCompensationFailed        = "compensation_failed"
	TaskEventCompensationNotApplicable = "compensation_not_applicable"
	TaskEventCredentialsDiscarded      = "credentials_discarded"
)

type TaskRunner interface {
	Check(context.Context, SSHDeploymentRequest) (CheckResult, error)
	Deploy(context.Context, SSHDeploymentRequest) (DeployResult, error)
}

type TaskCompensator interface {
	Compensate(context.Context, SSHDeploymentRequest, error) (CompensationResult, error)
}

type TaskEvent struct {
	Event     string    `json:"event"`
	Status    string    `json:"status,omitempty"`
	Stage     string    `json:"stage,omitempty"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Task struct {
	ID                 string              `json:"id"`
	Action             string              `json:"action"`
	Host               string              `json:"host"`
	User               string              `json:"user"`
	Port               int                 `json:"port"`
	Status             string              `json:"status"`
	Stage              string              `json:"stage"`
	Command            []string            `json:"command,omitempty"`
	Message            string              `json:"message,omitempty"`
	Output             string              `json:"output,omitempty"`
	OutputTruncated    bool                `json:"output_truncated,omitempty"`
	Error              string              `json:"error,omitempty"`
	StartedAt          time.Time           `json:"started_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
	FinishedAt         *time.Time          `json:"finished_at,omitempty"`
	Events             []TaskEvent         `json:"events,omitempty"`
	CheckResult        *CheckResult        `json:"check_result,omitempty"`
	DeployResult       *DeployResult       `json:"deploy_result,omitempty"`
	CompensationResult *CompensationResult `json:"compensation_result,omitempty"`
}

type TaskManagerOptions struct {
	Runner TaskRunner
	NewID  func() string
	Now    func() time.Time
}

type TaskManager struct {
	mu     sync.Mutex
	runner TaskRunner
	newID  func() string
	now    func() time.Time
	tasks  map[string]*taskRecord
}

type taskRecord struct {
	task Task
	req  SSHDeploymentRequest
}

func NewTaskManager(opts TaskManagerOptions) *TaskManager {
	runner := opts.Runner
	if runner == nil {
		runner = NewSSHRunner(SSHRunnerOptions{})
	}
	newID := opts.NewID
	if newID == nil {
		newID = randomTaskID
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &TaskManager{runner: runner, newID: newID, now: now, tasks: map[string]*taskRecord{}}
}

func (m *TaskManager) Start(ctx context.Context, req SSHDeploymentRequest) (Task, error) {
	if m == nil {
		return Task{}, fmt.Errorf("cluster deploy task manager is unavailable")
	}
	req = normalizeTaskRequest(req)
	if req.Action == "" {
		req.Action = actionCheck
	}
	if _, err := remoteCommandForAction(req.Action); err != nil {
		return Task{}, err
	}
	started := m.now()
	task := Task{
		ID:        m.nextID(),
		Action:    req.Action,
		Host:      strings.TrimSpace(req.Host),
		User:      strings.TrimSpace(req.User),
		Port:      normalizedSSHPort(req.Port),
		Status:    TaskStatusPending,
		Stage:     "queued",
		StartedAt: started,
		UpdatedAt: started,
	}
	appendTaskEvent(&task, TaskEventQueued, task.Status, task.Stage, "Task queued", started, req)
	m.mu.Lock()
	m.tasks[task.ID] = &taskRecord{task: task, req: req}
	m.mu.Unlock()
	go m.run(ctx, task.ID)
	return task, nil
}

func (m *TaskManager) Get(id string) (Task, bool) {
	if m == nil {
		return Task{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.tasks[strings.TrimSpace(id)]
	if !ok || record == nil {
		return Task{}, false
	}
	return sanitizeTask(record.task, record.req), true
}

func (m *TaskManager) List(limit int) []Task {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]Task, 0, len(m.tasks))
	for _, record := range m.tasks {
		if record == nil {
			continue
		}
		items = append(items, sanitizeTask(record.task, record.req))
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	return append([]Task(nil), items[:limit]...)
}

func (m *TaskManager) run(ctx context.Context, id string) {
	record := m.transition(id, TaskStatusRunning, TaskEventValidating, func(task *Task) {})
	if record == nil {
		return
	}
	if err := validateTaskSSHRequest(record.req); err != nil {
		m.finishValidationFailure(id, record.req, err)
		return
	}
	record = m.transition(id, TaskStatusRunning, TaskEventConnecting, func(task *Task) {})
	if record == nil {
		return
	}
	if record.req.Action == actionCheck {
		result, err := m.runner.Check(ctx, record.req)
		m.finishCheck(id, record.req, result, err)
		return
	}
	result, err := m.runner.Deploy(ctx, record.req)
	if err == nil {
		m.finishDeploy(id, record.req, result, nil)
		return
	}
	compensationResult, compensationErr, hasCompensation := m.compensateDeployFailure(ctx, id, record.req, err)
	m.finishDeployFailure(id, record.req, result, err, compensationResult, compensationErr, hasCompensation)
}

func (m *TaskManager) transition(id, status, stage string, mutate func(*Task)) *taskRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.tasks[id]
	if record == nil {
		return nil
	}
	now := m.now()
	record.task.Status = status
	record.task.Stage = stage
	record.task.UpdatedAt = now
	if mutate != nil {
		mutate(&record.task)
	}
	appendTaskEvent(&record.task, stage, status, stage, taskEventDefaultMessage(stage), now, record.req)
	return &taskRecord{task: record.task, req: record.req}
}

func (m *TaskManager) finishValidationFailure(id string, req SSHDeploymentRequest, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.tasks[id]
	if record == nil {
		return
	}
	now := m.now()
	record.task.Status = TaskStatusFailed
	record.task.Stage = TaskEventFailed
	record.task.Error = sanitizeTaskText(err.Error(), req)
	record.task.UpdatedAt = now
	record.task.FinishedAt = &now
	appendTaskEvent(&record.task, TaskEventFailed, TaskStatusFailed, TaskEventFailed, record.task.Error, now, req)
	discardTaskCredentials(record, now, req)
}

func (m *TaskManager) finishCheck(id string, req SSHDeploymentRequest, result CheckResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.tasks[id]
	if record == nil {
		return
	}
	now := m.now()
	status := TaskStatusSucceeded
	stage := "checked"
	event := TaskEventChecked
	if err != nil {
		status = TaskStatusFailed
		stage = "failed"
		event = TaskEventFailed
		record.task.Error = sanitizeTaskText(err.Error(), req)
	}
	result.Message = sanitizeTaskText(result.Message, req)
	result.Command = sanitizeTaskStrings(result.Command, req)
	record.task.Status = status
	record.task.Stage = stage
	record.task.Command = append([]string(nil), result.Command...)
	record.task.Message = result.Message
	record.task.CheckResult = &result
	record.task.UpdatedAt = now
	record.task.FinishedAt = &now
	appendTaskEvent(&record.task, event, status, stage, taskCompletionMessage(event, record.task.Message, record.task.Error), now, req)
	discardTaskCredentials(record, now, req)
}

func discardTaskCredentials(record *taskRecord, at time.Time, req SSHDeploymentRequest) {
	if record == nil {
		return
	}
	if hasTaskCredentials(record.req) || hasTaskCredentials(req) {
		appendTaskEvent(&record.task, TaskEventCredentialsDiscarded, record.task.Status, record.task.Stage, "One-time SSH credentials discarded", at, req)
	}
	record.req.Password = ""
	record.req.PrivateKey = ""
}

func (m *TaskManager) finishDeploy(id string, req SSHDeploymentRequest, result DeployResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.tasks[id]
	if record == nil {
		return
	}
	now := m.now()
	status := TaskStatusSucceeded
	stage := "deployed"
	event := TaskEventDeployed
	if err != nil {
		status = TaskStatusFailed
		stage = "failed"
		event = TaskEventFailed
		record.task.Error = sanitizeTaskText(err.Error(), req)
	}
	result.Output = sanitizeTaskText(result.Output, req)
	record.task.Status = status
	record.task.Stage = stage
	record.task.Output = result.Output
	record.task.OutputTruncated = result.OutputTruncated
	record.task.DeployResult = &result
	record.task.UpdatedAt = now
	record.task.FinishedAt = &now
	appendTaskEvent(&record.task, event, status, stage, taskCompletionMessage(event, record.task.Output, record.task.Error), now, req)
	discardTaskCredentials(record, now, req)
}

func (m *TaskManager) compensateDeployFailure(ctx context.Context, id string, req SSHDeploymentRequest, cause error) (CompensationResult, error, bool) {
	compensator, ok := m.runner.(TaskCompensator)
	if !ok || compensator == nil {
		result := CompensationResult{
			Attempted: false,
			Status:    CompensationStatusNotApplicable,
			Action:    compensationNone,
			Message:   "No compensation handler is available for this deployment runner",
		}
		m.recordCompensationEvent(id, req, result, nil)
		return result, nil, true
	}
	m.transition(id, TaskStatusRunning, TaskEventCompensating, func(task *Task) {})
	result, err := compensator.Compensate(ctx, req, cause)
	result = sanitizeCompensationResult(result, req)
	if err != nil && strings.TrimSpace(result.Status) == "" {
		result.Status = CompensationStatusFailed
	}
	m.recordCompensationEvent(id, req, result, err)
	return result, err, true
}

func (m *TaskManager) recordCompensationEvent(id string, req SSHDeploymentRequest, result CompensationResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.tasks[id]
	if record == nil {
		return
	}
	now := m.now()
	result = sanitizeCompensationResult(result, req)
	event := TaskEventCompensated
	message := result.Message
	if result.Status == CompensationStatusNotApplicable {
		event = TaskEventCompensationNotApplicable
	} else if err != nil || result.Status == CompensationStatusFailed {
		event = TaskEventCompensationFailed
		if result.Error != "" {
			message = result.Error
		} else if err != nil {
			message = err.Error()
		}
	}
	record.task.CompensationResult = &result
	record.task.UpdatedAt = now
	appendTaskEvent(&record.task, event, record.task.Status, event, message, now, req)
}

func (m *TaskManager) finishDeployFailure(id string, req SSHDeploymentRequest, result DeployResult, deployErr error, compensationResult CompensationResult, compensationErr error, hasCompensation bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.tasks[id]
	if record == nil {
		return
	}
	now := m.now()
	result.Output = sanitizeTaskText(result.Output, req)
	record.task.Status = TaskStatusFailed
	record.task.Stage = TaskEventFailed
	record.task.Error = sanitizeTaskText(deployErr.Error(), req)
	record.task.Output = result.Output
	record.task.OutputTruncated = result.OutputTruncated
	record.task.DeployResult = &result
	if hasCompensation {
		compensationResult = sanitizeCompensationResult(compensationResult, req)
		if compensationErr != nil && compensationResult.Error == "" {
			compensationResult.Error = sanitizeTaskText(compensationErr.Error(), req)
		}
		record.task.CompensationResult = &compensationResult
	}
	record.task.UpdatedAt = now
	record.task.FinishedAt = &now
	appendTaskEvent(&record.task, TaskEventFailed, TaskStatusFailed, TaskEventFailed, record.task.Error, now, req)
	discardTaskCredentials(record, now, req)
}

func (m *TaskManager) nextID() string {
	for attempts := 0; attempts < 8; attempts++ {
		id := strings.TrimSpace(m.newID())
		if id == "" {
			id = randomTaskID()
		}
		if !m.taskIDExists(id) {
			return id
		}
	}
	for {
		id := randomTaskID()
		if !m.taskIDExists(id) {
			return id
		}
	}
}

func (m *TaskManager) taskIDExists(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.tasks[id]
	return exists
}

func normalizeTaskRequest(req SSHDeploymentRequest) SSHDeploymentRequest {
	req.Host = strings.TrimSpace(req.Host)
	req.User = strings.TrimSpace(req.User)
	req.Password = strings.TrimSpace(req.Password)
	req.PrivateKey = strings.TrimSpace(req.PrivateKey)
	req.HostKeySHA256 = normalizeHostKeyFingerprint(req.HostKeySHA256)
	req.Action = strings.TrimSpace(req.Action)
	return req
}

func sanitizeTask(task Task, req SSHDeploymentRequest) Task {
	task.Command = sanitizeTaskStrings(task.Command, req)
	task.Message = sanitizeTaskText(task.Message, req)
	task.Output = sanitizeTaskText(task.Output, req)
	task.Error = sanitizeTaskText(task.Error, req)
	task.Events = sanitizeTaskEvents(task.Events, req)
	if task.CheckResult != nil {
		result := *task.CheckResult
		result.Command = sanitizeTaskStrings(result.Command, req)
		result.Message = sanitizeTaskText(result.Message, req)
		task.CheckResult = &result
	}
	if task.DeployResult != nil {
		result := *task.DeployResult
		result.Output = sanitizeTaskText(result.Output, req)
		task.DeployResult = &result
	}
	if task.CompensationResult != nil {
		result := sanitizeCompensationResult(*task.CompensationResult, req)
		task.CompensationResult = &result
	}
	return task
}

var (
	sensitiveAssignmentPattern = regexp.MustCompile(`(?i)(["']?\b(?:password|passwd|pwd|secret|api[_ -]?key|apikey|private[_ -]?key|privatekey|token|api[_ -]?token|access[_ -]?token|refresh[_ -]?token|session[_ -]?token|auth[_ -]?token)\b["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}\]]+)`)
	authTokenPattern           = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*(?:bearer|token|basic)\s+)[A-Za-z0-9._~+/=-]+`)
	bearerTokenPattern         = regexp.MustCompile(`(?i)\b((?:bearer|token)\s+)[A-Za-z0-9._~+/=-]+`)
)

func appendTaskEvent(task *Task, event, status, stage, message string, at time.Time, req SSHDeploymentRequest) {
	if task == nil {
		return
	}
	task.Events = append(task.Events, TaskEvent{
		Event:     event,
		Status:    status,
		Stage:     stage,
		Message:   strings.TrimSpace(sanitizeTaskText(message, req)),
		Timestamp: at,
	})
}

func sanitizeTaskEvents(events []TaskEvent, req SSHDeploymentRequest) []TaskEvent {
	if len(events) == 0 {
		return nil
	}
	out := make([]TaskEvent, len(events))
	for index, event := range events {
		out[index] = event
		out[index].Message = sanitizeTaskText(event.Message, req)
	}
	return out
}

func sanitizeTaskStrings(values []string, req SSHDeploymentRequest) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = sanitizeTaskText(value, req)
	}
	return out
}

func sanitizeTaskText(value string, req SSHDeploymentRequest) string {
	value = sanitizeCredentialText(value, req)
	value = sensitiveAssignmentPattern.ReplaceAllString(value, `${1}<redacted>`)
	value = authTokenPattern.ReplaceAllString(value, `${1}<redacted>`)
	value = bearerTokenPattern.ReplaceAllString(value, `${1}<redacted>`)
	return value
}

func sanitizeCompensationResult(result CompensationResult, req SSHDeploymentRequest) CompensationResult {
	result.Action = sanitizeTaskText(result.Action, req)
	result.Message = sanitizeTaskText(result.Message, req)
	result.Output = sanitizeTaskText(result.Output, req)
	result.Error = sanitizeTaskText(result.Error, req)
	return result
}

func taskEventDefaultMessage(event string) string {
	switch event {
	case TaskEventValidating:
		return "Validating request locally"
	case TaskEventConnecting:
		return "Connecting to remote host"
	case TaskEventCompensating:
		return "Attempting deployment compensation"
	default:
		return ""
	}
}

func taskCompletionMessage(event, detail, fallback string) string {
	if event == TaskEventFailed {
		return fallback
	}
	if strings.TrimSpace(detail) != "" {
		return detail
	}
	switch event {
	case TaskEventChecked:
		return "SSH check completed"
	case TaskEventDeployed:
		return "Deployment completed"
	default:
		return ""
	}
}

func hasTaskCredentials(req SSHDeploymentRequest) bool {
	return strings.TrimSpace(req.Password) != "" || strings.TrimSpace(req.PrivateKey) != ""
}

func validateTaskSSHRequest(req SSHDeploymentRequest) error {
	runner := NewSSHRunner(SSHRunnerOptions{})
	_, err := runner.BuildSSHArgs(req)
	return err
}

func randomTaskID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("deploy-%d", time.Now().UTC().UnixNano())
	}
	return "deploy-" + hex.EncodeToString(raw[:])
}
