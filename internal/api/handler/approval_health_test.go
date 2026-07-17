package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestHealthReportsUnavailableApprovalPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt approval file: %v", err)
	}
	store, err := ai.NewPersistentApprovalStore(path)
	if err == nil {
		t.Fatal("expected persistent approval store error")
	}
	cfg := config.Default()
	h := New(Options{Config: &cfg, AssistantApprovals: store})
	recorder := httptest.NewRecorder()
	h.Health(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))

	var response dto.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	data, ok := response.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected health data: %#v", response.Data)
	}
	if data["status"] != "degraded" {
		t.Fatalf("expected degraded health, got %#v", data)
	}
	persistence, ok := data["ai_approval_persistence"].(map[string]any)
	if !ok || persistence["healthy"] != false {
		t.Fatalf("unexpected approval persistence health: %#v", data["ai_approval_persistence"])
	}
}
