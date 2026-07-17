package ai

import (
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
	if _, err := assistant.ExecuteTool(context.Background(), "fake_modify", nil, ""); err == nil || !strings.Contains(err.Error(), "persistence is unavailable") {
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

type approvalReadOnlyTool struct{}

func (approvalReadOnlyTool) Name() string                 { return "approval_read" }
func (approvalReadOnlyTool) Description() string          { return "read-only approval test" }
func (approvalReadOnlyTool) Sensitivity() ToolSensitivity { return ReadOnly }
func (approvalReadOnlyTool) Parameters() map[string]any   { return map[string]any{"type": "object"} }
func (approvalReadOnlyTool) Execute(context.Context, map[string]any) (*ToolResult, error) {
	return &ToolResult{Success: true, Output: "ok"}, nil
}
