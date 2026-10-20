package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type revisionCountingSink struct{ queries int }

func (s *revisionCountingSink) Write(context.Context, *storage.LogEntry) error { return nil }
func (s *revisionCountingSink) Close() error                                   { return nil }
func (s *revisionCountingSink) Flush(context.Context) error                    { return nil }
func (s *revisionCountingSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.queries++
	return []storage.LogEntry{{ID: "private-event", ClientIP: "203.0.113.7", URI: "/private", Action: "block"}}, 1, nil
}

func TestRevisionLocalAssistantNeverQueriesLogsWithoutPermission(t *testing.T) {
	cfg := config.Default()
	cfg.APISec.Permissions["limited-ai"] = []string{"write:ai", "use:ai"}
	sink := &revisionCountingSink{}
	h := New(Options{Config: &cfg, Sink: sink})
	r := httptest.NewRequest(http.MethodPost, "/ai/assistant", bytes.NewBufferString(`{"message":"hello"}`))
	r = r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "limited", ID: "session", Role: "limited-ai"}))
	w := httptest.NewRecorder()
	h.AIAssistant(w, r)
	if sink.queries != 0 {
		t.Fatalf("unauthorized local assistant queried logs %d times: %s", sink.queries, w.Body.String())
	}
}

type revisionSSEWriter struct {
	http.ResponseWriter
	deadline time.Time
}

func (w *revisionSSEWriter) SetWriteDeadline(d time.Time) error { w.deadline = d; return nil }
func (w *revisionSSEWriter) Flush()                             {}
func (w *revisionSSEWriter) FlushError() error                  { return errors.New("flush failed") }

func TestRevisionSSEPropagatesFlushFailure(t *testing.T) {
	w := &revisionSSEWriter{ResponseWriter: httptest.NewRecorder()}
	if err := writeAssistantSSE(w, w, "trace", map[string]string{"message": "hello"}); err == nil {
		t.Fatal("flush failure was ignored")
	}
	if d := time.Until(w.deadline); d <= 0 || d > 10*time.Second {
		t.Fatalf("write deadline is not bounded to 10 seconds: %s", d)
	}
}

func TestRevisionAIStoredKeyCannotMoveToUnsavedEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.AI.APIBase = "https://configured.example/v1"
	cfg.AI.APIKey = "stored-secret"
	h := New(Options{Config: &cfg})
	for _, invoke := range []func(http.ResponseWriter, *http.Request){h.TestAIConnection, h.AIModels} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/ai/test", strings.NewReader(`{"api_base":"http://127.0.0.1:1","allow_private_api_base":true}`))
		invoke(w, r)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "AI_API_KEY_REQUIRED") {
			t.Fatalf("stored key endpoint override: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestRevisionProtectionOffRequiresDestructiveRole(t *testing.T) {
	cfg := config.Default()
	h := New(Options{Config: &cfg})
	_, err := h.executeAssistantTool(ai.ContextWithApprovalActor(context.Background(), ai.ApprovalActor{Subject: "operator", SessionID: "session", Role: "operator", Permissions: []string{"write:protection"}}), "set_protection_level", map[string]any{"level": "off"}, "")
	if err == nil || !strings.Contains(err.Error(), "not allowed for role") {
		t.Fatalf("destructive argument bypassed role ceiling: %v", err)
	}
}

func TestRevisionProtectionOffTranslationsAreDestructive(t *testing.T) {
	tool := setProtectionLevelTool{}
	for _, level := range []string{"off", "关闭", "停用"} {
		if got := tool.SensitivityForArgs(map[string]any{"level": level}); got != ai.Destructive {
			t.Errorf("level %q sensitivity = %v, want destructive", level, got)
		}
	}
}

func TestRevisionAIApprovalConfirmationRequiresLocalTransport(t *testing.T) {
	cfg := config.Default()
	store := ai.NewApprovalStore()
	adapter, err := ai.NewGateApprovalAdapter(store, approval.NewGate(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &cfg, AssistantApprovals: store, AssistantGateApproval: adapter})
	claims := &middleware.Claims{Subject: "approver", ID: "session", Username: "admin", Role: "admin"}
	for name, invoke := range map[string]func(http.ResponseWriter, *http.Request){
		"start":   h.StartAIApprovalConfirmation,
		"confirm": h.ConfirmAIApproval,
	} {
		r := httptest.NewRequest(http.MethodPost, "/ai/tools/approvals/missing/confirmation", strings.NewReader(`{}`))
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, claims))
		w := httptest.NewRecorder()
		invoke(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AI_APPROVAL_CONFIRMATION_FORBIDDEN") {
			t.Errorf("%s remote confirmation status=%d body=%s", name, w.Code, w.Body.String())
		}

		local := httptest.NewRequest(http.MethodPost, "/ai/tools/approvals/missing/confirmation", strings.NewReader(`{}`))
		local = local.WithContext(context.WithValue(local.Context(), middleware.UserContextKey, claims))
		local = local.WithContext(context.WithValue(local.Context(), localApprovalTransportKey{}, true))
		localWriter := httptest.NewRecorder()
		invoke(localWriter, local)
		if localWriter.Code == http.StatusForbidden && strings.Contains(localWriter.Body.String(), "AI_APPROVAL_CONFIRMATION_FORBIDDEN") {
			t.Errorf("%s trusted local confirmation was rejected as remote: status=%d body=%s", name, localWriter.Code, localWriter.Body.String())
		}
	}
}

func TestRevisionHandlerUsesInjectedProductionAIGate(t *testing.T) {
	cfg := config.Default()
	store := ai.NewApprovalStore()
	gate := approval.NewGate(1)
	adapter, err := ai.NewGateApprovalAdapter(store, gate, 1)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &cfg, AssistantApprovals: store, AssistantGateApproval: adapter})
	ctx := ai.ContextWithApprovalActor(context.Background(), ai.ApprovalActor{Subject: "admin", SessionID: "s1", Role: "admin"})
	call, err := h.executeAssistantTool(ctx, "set_protection_level", map[string]any{"area": "web_attack", "level": "off"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if call.Approval == nil || call.Approval.Status != ai.ApprovalPending {
		t.Fatalf("injected production gate did not create a pending approval: %#v", call)
	}
}

func TestRevisionAITokenCannotDecideApprovalsWithNonCanonicalIdentity(t *testing.T) {
	cfg := config.Default()
	h := New(Options{Config: &cfg})
	for _, claims := range []*middleware.Claims{
		{ID: "token", Subject: "human", Role: "API_TOKEN"},
		{ID: "token", Subject: "API-TOKEN:abc", Role: "approver"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/ai/approvals/missing/approve", nil)
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, claims))
		if h.canDecideAIApproval(r, "missing") {
			t.Fatalf("API token identity was accepted: %+v", claims)
		}
	}
}

func TestRevisionAISaveValidatesConfiguredPromptRegistry(t *testing.T) {
	cfg := config.Default().AI
	cfg.Prompts = []config.AIPromptConfig{{ID: "bad id", Version: "1", Content: "content", Enabled: true}}
	if err := validateAIConfigForSave(cfg); err == nil {
		t.Fatal("invalid prompt registry accepted")
	}
}
