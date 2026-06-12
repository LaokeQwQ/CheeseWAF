package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestUpdateSystemNotifiesAPISecReload(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var calls int
	var reloaded config.APISecConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnAPISecChanged: func(next config.APISecConfig) error {
			calls++
			reloaded = next
			return nil
		},
	})

	nextAPISec := cfg.APISec
	nextAPISec.Enabled = true
	nextAPISec.Validation.Enabled = true
	nextAPISec.Validation.Schemas = []config.APIEndpointSchemaConfig{{
		ID: "search", Method: http.MethodGet, PathPattern: "^/api/search$", RequiredParams: []string{"q"}, Enabled: true,
	}}
	nextAPISec.RateLimits = []config.APIEndpointLimitConfig{{
		ID: "search-rate", Method: http.MethodGet, PathPattern: "^/api/search$", Requests: 2, Window: time.Minute, Enabled: true,
	}}
	raw, _ := json.Marshal(map[string]any{"apisec": nextAPISec})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected system update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected one API security reload callback, got %d", calls)
	}
	if !reloaded.Enabled || len(reloaded.Validation.Schemas) != 1 || len(reloaded.RateLimits) != 1 {
		t.Fatalf("unexpected APISec reload payload: %+v", reloaded)
	}
	if cfg.APISec.Validation.Schemas[0].ID != "search" || cfg.APISec.RateLimits[0].ID != "search-rate" {
		t.Fatalf("system config was not updated: %+v", cfg.APISec)
	}
}

func TestUpdateSystemPersistsConsoleSecurityEntry(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	nextConsole := cfg.Console
	nextConsole.Login.SecurityEntry.Enabled = true
	nextConsole.Login.SecurityEntry.Path = "/ops-door"
	nextConsole.Login.SecurityEntry.CookieName = "cw_ops_entry"
	raw, _ := json.Marshal(map[string]any{"console": nextConsole})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected system update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !cfg.Console.Login.SecurityEntry.Enabled || cfg.Console.Login.SecurityEntry.Path != "/ops-door" || cfg.Console.Login.SecurityEntry.CookieName != "cw_ops_entry" {
		t.Fatalf("security entry was not updated in memory: %+v", cfg.Console.Login.SecurityEntry)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !loaded.Console.Login.SecurityEntry.Enabled || loaded.Console.Login.SecurityEntry.Path != "/ops-door" || loaded.Console.Login.SecurityEntry.CookieName != "cw_ops_entry" {
		t.Fatalf("security entry was not persisted: %+v", loaded.Console.Login.SecurityEntry)
	}
}

func TestUpdateBlockPageConfigPersistsAndNotifies(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls int
	var reloaded config.BlockPageConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls++
			reloaded = next
			return nil
		},
	})
	payload := config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body>{{.TraceID}}</body></html>`,
	}
	raw, _ := json.Marshal(payload)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/block-pages/config", bytes.NewReader(raw))
	handler.UpdateBlockPageConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected block page update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls != 1 || !reloaded.CustomEnabled {
		t.Fatalf("expected block page reload callback, calls=%d payload=%+v", calls, reloaded)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML == "" {
		t.Fatalf("block page config was not persisted: %+v", loaded.BlockPage)
	}
}

func TestWriteErrorIncludesTraceID(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, http.StatusBadRequest, "BAD_REQUEST", "bad")
	if recorder.Header().Get("X-CheeseWAF-Trace-ID") == "" {
		t.Fatal("expected trace id response header")
	}
	var body struct {
		Error struct {
			TraceID string `json:"trace_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.TraceID == "" || body.Error.TraceID != recorder.Header().Get("X-CheeseWAF-Trace-ID") {
		t.Fatalf("trace id mismatch header=%q body=%q", recorder.Header().Get("X-CheeseWAF-Trace-ID"), body.Error.TraceID)
	}
}
