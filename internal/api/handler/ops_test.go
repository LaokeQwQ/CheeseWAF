package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestListTasksReturnsReadableDurations(t *testing.T) {
	cfg := config.Default()
	cfg.Scheduler.Tasks = []config.ScheduledTaskConfig{{
		ID:        "log-cleanup",
		Name:      "Log cleanup",
		Type:      "cleanup",
		Frequency: "interval",
		Every:     24 * time.Hour,
		Target:    "./logs",
		Keep:      14,
		Enabled:   true,
	}}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/scheduler/tasks", nil)
	handler.ListTasks(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected list tasks ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "86400000000000") {
		t.Fatalf("duration leaked as raw nanoseconds: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"every":"1d"`) {
		t.Fatalf("expected readable duration, body=%s", recorder.Body.String())
	}
}

func TestUpdateTasksAcceptsReadableDurationsAndWrappedPayload(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})
	body := []byte(`{"tasks":[{"id":"security-report","name":"Security report","type":"security_report","frequency":"daily","every":"24h","at":"09:30","target":"","keep":7,"enabled":true}]}`)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/scheduler/tasks", bytes.NewReader(body))
	handler.UpdateTasks(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected update tasks ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(cfg.Scheduler.Tasks) != 1 || cfg.Scheduler.Tasks[0].Every != 24*time.Hour || cfg.Scheduler.Tasks[0].Channel != "file" {
		t.Fatalf("task was not normalized in memory: %+v", cfg.Scheduler.Tasks)
	}
	var response struct {
		Data []struct {
			Every string `json:"every"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if got := response.Data[0].Every; got != "1d" {
		t.Fatalf("expected readable response duration, got %q", got)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loaded.Scheduler.Tasks) != 1 || loaded.Scheduler.Tasks[0].Every != 24*time.Hour {
		t.Fatalf("task was not persisted with parsed duration: %+v", loaded.Scheduler.Tasks)
	}
}

func TestUpdateTasksAcceptsDayDurationFromListResponse(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})
	body := []byte(`[{"id":"log-cleanup","name":"Log cleanup","type":"cleanup","frequency":"interval","every":"1d","target":"./logs","keep":14,"enabled":true}]`)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/scheduler/tasks", bytes.NewReader(body))
	handler.UpdateTasks(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected update tasks ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(cfg.Scheduler.Tasks) != 1 || cfg.Scheduler.Tasks[0].Every != 24*time.Hour {
		t.Fatalf("expected 1d parsed as 24h, got %+v", cfg.Scheduler.Tasks)
	}
}

func TestUpdateTasksRejectsUnsafeWebhookEvenWithoutConfigPath(t *testing.T) {
	cfg := config.Default()
	cfg.Scheduler.Tasks = []config.ScheduledTaskConfig{{
		ID:        "existing-cleanup",
		Name:      "Existing cleanup",
		Type:      "cleanup",
		Frequency: "interval",
		Every:     24 * time.Hour,
		Target:    "./logs",
		Keep:      14,
		Enabled:   true,
	}}
	handler := New(Options{Config: &cfg})
	body := []byte(`[{"id":"unsafe-report","name":"Unsafe report","type":"security_report","frequency":"daily","channel":"webhook","recipient":"http://127.0.0.1:8080/hook","enabled":true}]`)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/scheduler/tasks", bytes.NewReader(body))
	handler.UpdateTasks(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid scheduler task to return 400, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "SCHEDULER_TASK_INVALID") {
		t.Fatalf("expected scheduler validation error code, body=%s", recorder.Body.String())
	}
	if len(cfg.Scheduler.Tasks) != 1 || cfg.Scheduler.Tasks[0].ID != "existing-cleanup" {
		t.Fatalf("invalid task should not replace existing config, got %+v", cfg.Scheduler.Tasks)
	}
}

func TestUpdateTasksSaveFailureKeepsPreviousConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Scheduler.Tasks = []config.ScheduledTaskConfig{{
		ID: "existing-cleanup", Name: "Existing cleanup", Type: "cleanup",
		Frequency: "interval", Every: 24 * time.Hour, Target: "./logs", Keep: 14, Enabled: true,
	}}
	handler := New(Options{Config: &cfg, ConfigPath: t.TempDir()})
	body := []byte(`[{"id":"replacement-cleanup","name":"Replacement cleanup","type":"cleanup","frequency":"interval","every":"12h","target":"./logs","keep":7,"enabled":true}]`)

	recorder := httptest.NewRecorder()
	handler.UpdateTasks(recorder, httptest.NewRequest(http.MethodPut, "/api/scheduler/tasks", bytes.NewReader(body)))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected save failure, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(cfg.Scheduler.Tasks) != 1 || cfg.Scheduler.Tasks[0].ID != "existing-cleanup" {
		t.Fatalf("save failure changed scheduler config: %+v", cfg.Scheduler.Tasks)
	}
}

func TestUpdateEdgePolicySaveFailureKeepsPreviousConfig(t *testing.T) {
	cfg := config.Default()
	previous := cfg.Edge
	next := cfg.Edge
	next.Headers.Enabled = !previous.Headers.Enabled
	body, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: t.TempDir()})

	recorder := httptest.NewRecorder()
	handler.UpdateEdgePolicy(recorder, httptest.NewRequest(http.MethodPut, "/api/edge", bytes.NewReader(body)))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected save failure, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.Edge.Headers.Enabled != previous.Headers.Enabled {
		t.Fatalf("save failure changed edge config: %+v", cfg.Edge)
	}
}

func TestUpdateBlockPageSaveFailureRollsBackRuntime(t *testing.T) {
	cfg := config.Default()
	previous := cfg.BlockPage
	next := previous
	next.TemplateID = "brand"
	if next.TemplateID == previous.TemplateID {
		next.TemplateID = "technical"
	}
	body, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	var applied []config.BlockPageConfig
	handler := New(Options{
		Config: &cfg, ConfigPath: t.TempDir(),
		OnBlockPageChanged: func(candidate config.BlockPageConfig) error {
			applied = append(applied, candidate)
			return nil
		},
	})

	recorder := httptest.NewRecorder()
	handler.UpdateBlockPageConfig(recorder, httptest.NewRequest(http.MethodPut, "/api/block-page", bytes.NewReader(body)))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected save failure, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.BlockPage != previous {
		t.Fatalf("save failure changed block page config: %+v", cfg.BlockPage)
	}
	if len(applied) != 2 || applied[0] != next || applied[1] != previous {
		t.Fatalf("runtime apply/rollback sequence = %+v, want [%+v %+v]", applied, next, previous)
	}
}

func TestImportNginxRejectsOversizedBody(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/nginx/import", strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	handler.ImportNginx(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected oversized nginx import to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "NGINX_IMPORT_TOO_LARGE") {
		t.Fatalf("expected NGINX_IMPORT_TOO_LARGE, body=%s", recorder.Body.String())
	}
}

func TestStorageStatsUsesCachedDirectorySizes(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "state.db"), []byte("12345"), 0o600); err != nil {
		t.Fatalf("write data fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "access.log"), []byte("abcdef"), 0o600); err != nil {
		t.Fatalf("write log fixture: %v", err)
	}
	cfg := config.Default()
	cfg.Setup.DataDir = dataDir
	cfg.Logging.Output.File.Path = filepath.Join(logDir, "cheesewaf.log")
	handler := New(Options{Config: &cfg})

	first := storageStatsResponse(t, handler)
	if first.DataSize != 5 || first.LogSize != 6 {
		t.Fatalf("expected initial directory sizes 5/6, got %+v", first)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "state.db"), []byte(strings.Repeat("x", 50)), 0o600); err != nil {
		t.Fatalf("rewrite data fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "access.log"), []byte(strings.Repeat("y", 60)), 0o600); err != nil {
		t.Fatalf("rewrite log fixture: %v", err)
	}
	second := storageStatsResponse(t, handler)
	if second.DataSize != first.DataSize || second.LogSize != first.LogSize {
		t.Fatalf("expected cached directory sizes within TTL, first=%+v second=%+v", first, second)
	}
}

type storageStatsPayload struct {
	DataSize int64 `json:"data"`
	LogSize  int64 `json:"logs"`
}

func storageStatsResponse(t *testing.T, handler *Handler) storageStatsPayload {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/ops/storage", nil)
	handler.StorageStats(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected storage stats ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data storageStatsPayload `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode storage stats: %v", err)
	}
	return response.Data
}
