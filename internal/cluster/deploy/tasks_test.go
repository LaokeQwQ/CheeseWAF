package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTaskManagerStoresRedactedDeploymentResult(t *testing.T) {
	secret := "task-secret"
	token := "deploy-token-secret"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubTaskRunner{deployResult: DeployResult{OK: true, Host: "node-a", Output: "ok " + secret + " token=" + token + " api_token=" + token + " access_token=" + token + " privateKey=" + secret + " Authorization: Token " + token}},
		NewID:  func() string { return "task-a" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-a", User: "root", Password: secret, Action: "install"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusSucceeded)
	assertTaskNoSecrets(t, task, secret, token)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventDeployed, TaskEventCredentialsDiscarded)
	if task.Output != "ok <redacted> token=<redacted> api_token=<redacted> access_token=<redacted> privateKey=<redacted> Authorization: Token <redacted>" {
		t.Fatalf("task output was not safely redacted: %+v", task)
	}
	if !taskHasEventMessage(task, TaskEventDeployed, "ok <redacted> token=<redacted> api_token=<redacted> access_token=<redacted> privateKey=<redacted> Authorization: Token <redacted>") {
		t.Fatalf("deployed event did not record sanitized output: %+v", task.Events)
	}
	if !taskHasEventMessage(task, TaskEventCredentialsDiscarded, "One-time SSH credentials discarded") {
		t.Fatalf("task did not record credential discard event: %+v", task.Events)
	}
	items := manager.List(10)
	if len(items) != 1 {
		t.Fatalf("task list length=%d, want 1", len(items))
	}
	assertTaskNoSecrets(t, items[0], secret, token)
	assertTaskEvents(t, items[0], TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventDeployed, TaskEventCredentialsDiscarded)
}

func TestTaskManagerStoresRedactedCheckTimeline(t *testing.T) {
	secret := "check-secret"
	token := "check-token-secret"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubTaskRunner{checkResult: CheckResult{OK: true, Host: "node-check", Message: "ready password=" + secret + " bearer " + token}},
		NewID:  func() string { return "task-check" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-check", User: "root", Password: secret, Action: "check"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusSucceeded)
	assertTaskNoSecrets(t, task, secret, token)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventChecked, TaskEventCredentialsDiscarded)
	if task.Message != "ready password=<redacted> bearer <redacted>" {
		t.Fatalf("task message was not safely redacted: %+v", task)
	}
	if !taskHasEventMessage(task, TaskEventChecked, "ready password=<redacted> bearer <redacted>") {
		t.Fatalf("checked event did not record sanitized message: %+v", task.Events)
	}
}

func TestTaskManagerStoresRedactedFailure(t *testing.T) {
	secret := "private-key-secret"
	token := "failure-token-secret"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubTaskRunner{deployErr: errors.New("failed with " + secret + " private_key=" + secret + " token=" + token)},
		NewID:  func() string { return "task-b" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-b", User: "root", Password: secret, Action: "restart-service"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusFailed)
	assertTaskNoSecrets(t, task, secret, token)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventCompensationNotApplicable, TaskEventFailed, TaskEventCredentialsDiscarded)
	if !strings.Contains(task.Error, "<redacted>") {
		t.Fatalf("task error should retain useful redaction marker: %+v", task)
	}
	if !taskHasEventMessage(task, TaskEventFailed, "failed with <redacted> private_key=<redacted> token=<redacted>") {
		t.Fatalf("failed event did not record sanitized error: %+v", task.Events)
	}
	items := manager.List(10)
	if len(items) != 1 {
		t.Fatalf("task list length=%d, want 1", len(items))
	}
	assertTaskNoSecrets(t, items[0], secret, token)
}

func TestTaskManagerRestartServiceFailureCompensationSucceeded(t *testing.T) {
	secret := "restart-secret"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubCompensatingTaskRunner{
			stubTaskRunner: stubTaskRunner{
				deployResult: DeployResult{OK: false, Host: "node-restart", Output: "restart failed"},
				deployErr:    errors.New("restart failed"),
			},
			compensateResult: CompensationResult{
				Attempted: true,
				Status:    CompensationStatusSucceeded,
				Action:    compensationStartService,
				Message:   "service start attempted",
				Output:    "service started",
			},
		},
		NewID: func() string { return "task-restart-compensated" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-restart", User: "root", Password: secret, Action: "restart-service"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusFailed)
	assertTaskNoSecrets(t, task, secret)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventCompensating, TaskEventCompensated, TaskEventFailed, TaskEventCredentialsDiscarded)
	if task.CompensationResult == nil || task.CompensationResult.Status != CompensationStatusSucceeded {
		t.Fatalf("task compensation result=%+v, want succeeded", task.CompensationResult)
	}
	if task.Status != TaskStatusFailed {
		t.Fatalf("task status=%q, want failed even after compensation success", task.Status)
	}
}

func TestTaskManagerRestartServiceFailureCompensationFailed(t *testing.T) {
	secret := "restart-fail-secret"
	token := "restart-fail-token"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubCompensatingTaskRunner{
			stubTaskRunner: stubTaskRunner{
				deployResult: DeployResult{OK: false, Host: "node-restart", Output: "restart failed"},
				deployErr:    errors.New("restart failed"),
			},
			compensateResult: CompensationResult{
				Attempted: true,
				Status:    CompensationStatusFailed,
				Action:    compensationStartService,
				Message:   "start failed password=" + secret,
				Error:     "systemctl start failed token=" + token,
			},
			compensateErr: errors.New("systemctl start failed token=" + token),
		},
		NewID: func() string { return "task-restart-compensation-failed" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-restart", User: "root", Password: secret, Action: "restart-service"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusFailed)
	assertTaskNoSecrets(t, task, secret, token)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventCompensating, TaskEventCompensationFailed, TaskEventFailed, TaskEventCredentialsDiscarded)
	if task.CompensationResult == nil || task.CompensationResult.Status != CompensationStatusFailed {
		t.Fatalf("task compensation result=%+v, want failed", task.CompensationResult)
	}
	if !taskHasEventMessage(task, TaskEventCompensationFailed, "systemctl start failed token=<redacted>") {
		t.Fatalf("compensation_failed event did not record sanitized error: %+v", task.Events)
	}
}

func TestTaskManagerInstallFailureCompensationNotApplicable(t *testing.T) {
	secret := "install-secret"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubCompensatingTaskRunner{
			stubTaskRunner: stubTaskRunner{
				deployResult: DeployResult{OK: false, Host: "node-install", Output: "install failed"},
				deployErr:    errors.New("install failed"),
			},
			compensateResult: CompensationResult{
				Attempted: false,
				Status:    CompensationStatusNotApplicable,
				Action:    compensationNone,
				Message:   "The install action performs inline backup and restore when possible; no separate compensation action is available after the SSH session ends",
			},
		},
		NewID: func() string { return "task-install-not-applicable" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-install", User: "root", Password: secret, Action: "install"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusFailed)
	assertTaskNoSecrets(t, task, secret)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventConnecting, TaskEventCompensating, TaskEventCompensationNotApplicable, TaskEventFailed, TaskEventCredentialsDiscarded)
	if task.CompensationResult == nil || task.CompensationResult.Status != CompensationStatusNotApplicable || task.CompensationResult.Attempted {
		t.Fatalf("task compensation result=%+v, want not applicable and not attempted", task.CompensationResult)
	}
	if strings.Contains(strings.ToLower(task.CompensationResult.Message), "rollback") {
		t.Fatalf("install compensation message must not imply rollback: %q", task.CompensationResult.Message)
	}
}

func TestTaskManagerValidationFailureDoesNotRecordConnecting(t *testing.T) {
	secret := "validation-secret"
	runner := &stubCompensatingTaskRunner{
		stubTaskRunner: stubTaskRunner{deployResult: DeployResult{OK: true, Host: "unused", Output: secret}},
	}
	manager := NewTaskManager(TaskManagerOptions{
		Runner: runner,
		NewID:  func() string { return "task-validation" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "127.0.0.1;id", User: "root", Password: secret, Action: "install"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusFailed)
	assertTaskNoSecrets(t, task, secret)
	assertTaskEvents(t, task, TaskEventQueued, TaskEventValidating, TaskEventFailed, TaskEventCredentialsDiscarded)
	for _, event := range task.Events {
		switch event.Event {
		case TaskEventConnecting, TaskEventCompensating, TaskEventCompensated, TaskEventCompensationFailed, TaskEventCompensationNotApplicable:
			t.Fatalf("local validation failure must not record remote or compensation event %q: %+v", event.Event, task.Events)
		}
	}
	if runner.compensateCalls != 0 {
		t.Fatalf("local validation failure must not compensate, calls=%d", runner.compensateCalls)
	}
}

func TestTaskManagerStoresRedactedCompensationOutput(t *testing.T) {
	secret := "compensation-secret"
	token := "compensation-token"
	manager := NewTaskManager(TaskManagerOptions{
		Runner: &stubCompensatingTaskRunner{
			stubTaskRunner: stubTaskRunner{
				deployResult: DeployResult{OK: false, Host: "node-redact", Output: "restart failed password=" + secret},
				deployErr:    errors.New("restart failed private_key=" + secret),
			},
			compensateResult: CompensationResult{
				Attempted: true,
				Status:    CompensationStatusSucceeded,
				Action:    compensationStartService,
				Message:   "message password=" + secret + " bearer " + token,
				Output:    "output token=" + token + " privateKey=" + secret,
			},
		},
		NewID: func() string { return "task-compensation-redacted" },
	})
	task, err := manager.Start(context.Background(), SSHDeploymentRequest{Host: "node-redact", User: "root", Password: secret, Action: "restart-service"})
	if err != nil {
		t.Fatal(err)
	}
	task = waitTaskStatus(t, manager, task.ID, TaskStatusFailed)
	assertTaskNoSecrets(t, task, secret, token)
	if task.CompensationResult == nil {
		t.Fatal("expected compensation result")
	}
	if task.CompensationResult.Message != "message password=<redacted> bearer <redacted>" {
		t.Fatalf("compensation message was not safely redacted: %+v", task.CompensationResult)
	}
	if task.CompensationResult.Output != "output token=<redacted> privateKey=<redacted>" {
		t.Fatalf("compensation output was not safely redacted: %+v", task.CompensationResult)
	}
}

func TestSanitizeTaskRedactsEventMessages(t *testing.T) {
	secret := "direct-secret"
	token := "direct-token-secret"
	task := sanitizeTask(Task{
		Events: []TaskEvent{{
			Event:   TaskEventFailed,
			Message: "password=" + secret + " private_key=" + secret + " privateKey=" + secret + " api_token=" + token + " access_token=" + token + " Authorization: Token " + token,
		}},
	}, SSHDeploymentRequest{Password: secret, PrivateKey: secret})
	if len(task.Events) != 1 {
		t.Fatalf("expected one event, got %+v", task.Events)
	}
	message := task.Events[0].Message
	if strings.Contains(message, secret) || strings.Contains(message, token) {
		t.Fatalf("task output leaked secret: %+v", task)
	}
	for _, want := range []string{"password=<redacted>", "private_key=<redacted>", "privateKey=<redacted>", "api_token=<redacted>", "access_token=<redacted>", "Authorization: Token <redacted>"} {
		if !strings.Contains(message, want) {
			t.Fatalf("event message missing redaction %q: %q", want, message)
		}
	}
}

type stubTaskRunner struct {
	checkResult  CheckResult
	checkErr     error
	deployResult DeployResult
	deployErr    error
}

func (r *stubTaskRunner) Check(context.Context, SSHDeploymentRequest) (CheckResult, error) {
	return r.checkResult, r.checkErr
}

func (r *stubTaskRunner) Deploy(context.Context, SSHDeploymentRequest) (DeployResult, error) {
	return r.deployResult, r.deployErr
}

type stubCompensatingTaskRunner struct {
	stubTaskRunner
	compensateResult CompensationResult
	compensateErr    error
	compensateCalls  int
}

func (r *stubCompensatingTaskRunner) Compensate(context.Context, SSHDeploymentRequest, error) (CompensationResult, error) {
	r.compensateCalls++
	return r.compensateResult, r.compensateErr
}

func waitTaskStatus(t *testing.T, manager *TaskManager, id string, want string) Task {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if task, ok := manager.Get(id); ok && task.Status == want {
			return task
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach status %s", id, want)
	return Task{}
}

func assertTaskNoSecrets(t *testing.T, task Task, secrets ...string) {
	t.Helper()
	text := taskText(task)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Fatalf("task leaked secret %q: %+v", secret, task)
		}
	}
	for _, forbidden := range []string{"password=" + secrets[0], "private_key=" + secrets[0]} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("task leaked sensitive assignment %q: %+v", forbidden, task)
		}
	}
}

func assertTaskEvents(t *testing.T, task Task, want ...string) {
	t.Helper()
	got := make([]string, 0, len(task.Events))
	for _, event := range task.Events {
		got = append(got, event.Event)
		if event.Timestamp.IsZero() {
			t.Fatalf("event %q has zero timestamp: %+v", event.Event, task.Events)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("events=%v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("events=%v, want %v", got, want)
		}
	}
}

func taskHasEventMessage(task Task, eventName, message string) bool {
	for _, event := range task.Events {
		if event.Event == eventName && event.Message == message {
			return true
		}
	}
	return false
}

func taskText(task Task) string {
	var b strings.Builder
	b.WriteString(task.Message)
	b.WriteString(task.Output)
	b.WriteString(task.Error)
	for _, value := range task.Command {
		b.WriteString(value)
	}
	for _, event := range task.Events {
		b.WriteString(event.Event)
		b.WriteString(event.Message)
	}
	if task.CheckResult != nil {
		b.WriteString(task.CheckResult.Message)
		for _, value := range task.CheckResult.Command {
			b.WriteString(value)
		}
	}
	if task.DeployResult != nil {
		b.WriteString(task.DeployResult.Output)
	}
	if task.CompensationResult != nil {
		b.WriteString(task.CompensationResult.Action)
		b.WriteString(task.CompensationResult.Message)
		b.WriteString(task.CompensationResult.Output)
		b.WriteString(task.CompensationResult.Error)
	}
	return b.String()
}
