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
