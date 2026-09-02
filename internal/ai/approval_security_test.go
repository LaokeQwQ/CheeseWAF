package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type approvalSecretFixture struct {
	Password string         `json:"password"`
	Nested   map[string]any `json:"nested"`
}

func TestApprovalPersistenceRedactsNestedSecretsAndKeepsDigestBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := NewPersistentApprovalStore(path)
	if err != nil {
		t.Fatalf("create persistent store: %v", err)
	}
	args := map[string]any{
		"fixture": approvalSecretFixture{
			Password: "outer-password",
			Nested: map[string]any{
				"authorization": "Bearer nested-token",
				"items":         []any{map[string]any{"apiKey": "nested-api-key", "authToken": "camel-token", "label": "visible"}},
			},
		},
		"private-key": "private-key-material",
	}
	request, err := store.CreateFor(fakeTool{sensitivity: Modify}, args, "", ApprovalActor{Subject: "user", SessionID: "session"})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read approval file: %v", err)
	}
	for _, secret := range []string{"outer-password", "nested-token", "nested-api-key", "camel-token", "private-key-material"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("approval file contains secret %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(string(encoded), redactedApprovalValue) {
		t.Fatalf("approval file does not contain redaction marker: %s", encoded)
	}
	if request.ArgsDigest == "" {
		t.Fatal("approval digest is empty")
	}
	publicJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal public approval: %v", err)
	}
	if strings.Contains(string(publicJSON), "args_salt") || strings.Contains(string(publicJSON), "args_digest") || strings.Contains(string(publicJSON), request.ArgsDigest) {
		t.Fatalf("public approval JSON exposes digest metadata: %s", publicJSON)
	}
	if !strings.Contains(string(encoded), `"args_salt"`) || !strings.Contains(string(encoded), `"args_digest"`) || !strings.Contains(string(encoded), request.ArgsDigest) {
		t.Fatalf("approval disk record is missing digest metadata: %s", encoded)
	}
	if fixture, ok := request.Args["fixture"].(map[string]any); !ok || fixture["password"] != redactedApprovalValue {
		t.Fatalf("API snapshot exposes fixture password: %#v", request.Args)
	}

	reloaded, err := NewPersistentApprovalStore(path)
	if err != nil {
		t.Fatalf("reload approval store: %v", err)
	}
	if _, err := reloaded.ApproveFor(request.ID, ApprovalActor{Subject: "user", SessionID: "session"}); err != nil {
		t.Fatalf("approve after reload: %v", err)
	}
	if _, err := reloaded.BeginExecutionFor(request.ID, "fake_modify", args, ApprovalActor{Subject: "user", SessionID: "session"}); err != nil {
		t.Fatalf("original arguments rejected after reload: %v", err)
	}
}

func TestApprovalPersistenceSanitizesStructuredAndTextDiffSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := NewPersistentApprovalStore(path)
	if err != nil {
		t.Fatalf("create persistent store: %v", err)
	}
	diffs := []string{
		`{"before":{"api_key":"json-secret"},"after":{"nested":[{"password":"json-password"}]}}`,
		"Authorization: Bearer header-secret\npassword=plain-secret\n'client_secret': 'quoted-secret'\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
	}
	for _, diff := range diffs {
		request, err := store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"enabled": true}, diff, ApprovalActor{})
		if err != nil {
			t.Fatalf("create approval with diff: %v", err)
		}
		if !strings.Contains(request.Diff, redactedApprovalValue) {
			t.Fatalf("approval diff was not redacted: %q", request.Diff)
		}
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read approval file: %v", err)
	}
	for _, secret := range []string{"json-secret", "json-password", "header-secret", "plain-secret", "quoted-secret", "private-material"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("approval file contains diff secret %q: %s", secret, encoded)
		}
	}
}

func TestApprovalDigestRejectsNestedArgumentTampering(t *testing.T) {
	store := NewApprovalStore()
	args := map[string]any{"nested": map[string]any{"token": "secret", "enabled": true}}
	request, err := store.CreateFor(fakeTool{sensitivity: Modify}, args, "", ApprovalActor{Subject: "user", SessionID: "session"})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if _, err := store.ApproveFor(request.ID, ApprovalActor{Subject: "user", SessionID: "session"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	tampered := map[string]any{"nested": map[string]any{"token": "secret", "enabled": false}}
	if _, err := store.BeginExecutionFor(request.ID, "fake_modify", tampered, ApprovalActor{Subject: "user", SessionID: "session"}); err == nil {
		t.Fatal("tampered arguments were accepted")
	}
}

func TestApprovalStoreCapacityEvictsOldestCompletedRequest(t *testing.T) {
	store := NewApprovalStore()
	store.capacity = 2
	first, err := store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"id": 1}, "", ApprovalActor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Approve(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.BeginExecution(first.ID, "fake_modify", map[string]any{"id": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.MarkExecuted(first.ID, ApprovalActor{}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"id": 2}, "", ApprovalActor{}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"id": 3}, "", ApprovalActor{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(first.ID); ok {
		t.Fatal("oldest completed approval was not evicted")
	}
	if got := len(store.List()); got != 2 {
		t.Fatalf("approval count = %d, want 2", got)
	}
}

func TestApprovalStoreCapacityRejectsWhenAllRequestsAreActive(t *testing.T) {
	store := NewApprovalStore()
	store.capacity = 2
	for id := 1; id <= 2; id++ {
		if _, err := store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"id": id}, "", ApprovalActor{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"id": 3}, "", ApprovalActor{}); err == nil {
		t.Fatal("expected active approval capacity exhaustion")
	}
	if got := len(store.List()); got != 2 {
		t.Fatalf("approval count = %d, want 2", got)
	}
}

func TestApprovalStoreRejectsOversizedPersistentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 65), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewApprovalStore()
	store.maxBytes = 64
	if err := store.UseFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded-read error, got %v", err)
	}
}

func TestAssistantFailsClosedForModificationWhenPersistenceUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("create corrupt approval file: %v", err)
	}
	store, err := NewPersistentApprovalStore(path)
	if err == nil {
		t.Fatal("expected persistent store initialization to fail")
	}
	if healthy, healthErr := store.PersistenceHealth(); healthy || healthErr == nil {
		t.Fatalf("unexpected persistence health: healthy=%v err=%v", healthy, healthErr)
	}

	registry := NewRegistry()
	registry.Register(fakeTool{sensitivity: Modify})
	registry.Register(approvalReadOnlyTool{})
	assistant := NewAssistant(registry, store)
	if _, err := assistant.ExecuteTool(testAdminAIContext(), "fake_modify", nil, ""); err == nil || !strings.Contains(err.Error(), "persistence is unavailable") {
		t.Fatalf("modification tool did not fail closed: %v", err)
	}
	result, err := assistant.ExecuteTool(context.Background(), "approval_read", nil, "")
	if err != nil {
		t.Fatalf("read-only tool should remain available: %v", err)
	}
	if result == nil || result.Result == nil || !result.Result.Success {
		t.Fatalf("unexpected read-only result: %#v", result)
	}
}

// finishExecution is the last gate of the dual-control chain. Entry points
// (Assistant.ExecuteTool) already refuse to start an execution they do not own,
// but MarkExecuted/MarkExecutionFailed are exported and reachable from any new
// call site, so the store has to refuse to finish somebody else's request on
// its own. Without this check, holding an approval id is enough to flip an
// in-flight change to executed/failed and strand its owner.
func TestApprovalFinishExecutionRejectsForeignRequester(t *testing.T) {
	owner := ApprovalActor{Subject: "owner", SessionID: "owner-session"}
	foreigners := map[string]ApprovalActor{
		"a different user":       {Subject: "approver", SessionID: "approver-session"},
		"same user, new session": {Subject: "owner", SessionID: "owner-session-2"},
		"same user, no session":  {Subject: "owner"},
		"no actor at all":        {},
	}
	finishers := map[string]func(*ApprovalStore, string, ApprovalActor) (ApprovalRequest, error){
		"MarkExecuted":        (*ApprovalStore).MarkExecuted,
		"MarkExecutionFailed": (*ApprovalStore).MarkExecutionFailed,
	}
	for finishName, finish := range finishers {
		for name, foreign := range foreigners {
			store := NewApprovalStore()
			request, err := store.CreateFor(fakeTool{sensitivity: Modify}, nil, "", owner)
			if err != nil {
				t.Fatalf("create approval: %v", err)
			}
			if _, err := store.ApproveFor(request.ID, ApprovalActor{Subject: "approver", SessionID: "approver-session"}); err != nil {
				t.Fatalf("approve: %v", err)
			}
			executing, err := store.BeginExecutionFor(request.ID, "fake_modify", nil, owner)
			if err != nil {
				t.Fatalf("begin execution: %v", err)
			}
			if _, err := finish(store, executing.ID, foreign); err == nil {
				t.Fatalf("%s let %s finalize the request", finishName, name)
			}
			stored, ok := store.Get(executing.ID)
			if !ok {
				t.Fatalf("%s dropped the request from the store", name)
			}
			if stored.Status != ApprovalExecuting {
				t.Fatalf("%s moved the request to %s", name, stored.Status)
			}
			if !stored.DecidedAt.Equal(executing.DecidedAt) {
				t.Fatalf("%s rewrote the decision timestamp: %s", name, stored.DecidedAt)
			}
			// A refused attempt must not burn the owner's request either.
			if _, err := store.MarkExecuted(executing.ID, owner); err != nil {
				t.Fatalf("%s left the owner unable to finish: %v", name, err)
			}
		}
	}
}

// The check added above must not break the normal path: the requester that
// started the execution still finishes it, in both outcomes.
func TestApprovalFinishExecutionAllowsOriginalRequester(t *testing.T) {
	owner := ApprovalActor{Subject: "owner", SessionID: "owner-session"}
	finishers := map[string]struct {
		finish func(*ApprovalStore, string, ApprovalActor) (ApprovalRequest, error)
		want   ApprovalStatus
	}{
		"MarkExecuted":        {(*ApprovalStore).MarkExecuted, ApprovalExecuted},
		"MarkExecutionFailed": {(*ApprovalStore).MarkExecutionFailed, ApprovalFailed},
	}
	for name, testCase := range finishers {
		store := NewApprovalStore()
		request, err := store.CreateFor(fakeTool{sensitivity: Modify}, nil, "", owner)
		if err != nil {
			t.Fatalf("create approval: %v", err)
		}
		if _, err := store.ApproveFor(request.ID, ApprovalActor{Subject: "approver", SessionID: "approver-session"}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if _, err := store.BeginExecutionFor(request.ID, "fake_modify", nil, owner); err != nil {
			t.Fatalf("begin execution: %v", err)
		}
		finished, err := testCase.finish(store, request.ID, owner)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if finished.Status != testCase.want {
			t.Fatalf("%s: status = %s, want %s", name, finished.Status, testCase.want)
		}
		if stored, _ := store.Get(request.ID); stored.Status != testCase.want {
			t.Fatalf("%s: persisted status = %s, want %s", name, stored.Status, testCase.want)
		}
		// The owner cannot finalize twice; the status gate, not the actor
		// gate, is what stops the replay.
		if _, err := testCase.finish(store, request.ID, owner); err == nil {
			t.Fatalf("%s: request was finalized twice", name)
		}
	}
}

// A request created without an actor (internal callers, or records written
// before requesters were recorded) stays finalizable by whoever reaches it, so
// the added check is a requester binding, not a blanket lockout.
func TestApprovalFinishExecutionAllowsRequestWithoutRequester(t *testing.T) {
	for name, finisher := range map[string]ApprovalActor{
		"no actor":    {},
		"named actor": {Subject: "operator", SessionID: "operator-session"},
	} {
		store := NewApprovalStore()
		request, err := store.CreateFor(fakeTool{sensitivity: Modify}, nil, "", ApprovalActor{})
		if err != nil {
			t.Fatalf("create approval: %v", err)
		}
		if request.RequesterSubject != "" {
			t.Fatalf("expected an unbound request, got subject %q", request.RequesterSubject)
		}
		if _, err := store.ApproveFor(request.ID, ApprovalActor{Subject: "approver", SessionID: "approver-session"}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if _, err := store.BeginExecutionFor(request.ID, "fake_modify", nil, ApprovalActor{}); err != nil {
			t.Fatalf("begin execution: %v", err)
		}
		if _, err := store.MarkExecuted(request.ID, finisher); err != nil {
			t.Fatalf("unbound request is no longer finalizable by %s: %v", name, err)
		}
	}
}

type approvalReadOnlyTool struct{}

func (approvalReadOnlyTool) Name() string                 { return "approval_read" }
func (approvalReadOnlyTool) Description() string          { return "read-only approval test" }
func (approvalReadOnlyTool) Sensitivity() ToolSensitivity { return ReadOnly }
func (approvalReadOnlyTool) Parameters() map[string]any   { return map[string]any{"type": "object"} }
func (approvalReadOnlyTool) Execute(context.Context, map[string]any) (*ToolResult, error) {
	return &ToolResult{Success: true, Output: "ok"}, nil
}
