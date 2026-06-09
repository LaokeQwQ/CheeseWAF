package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestAIConfigUsesProviderAndHidesHeader(t *testing.T) {
	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIKey = "existing-secret"
	cfg.AI.APIKeyHeader = "api-key"
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	body := []byte(`{"enabled":true,"provider":"anthropic","api_base":"https://api.anthropic.com/v1","api_key":"","api_key_header":"x-api-key","model":"claude-3-5-haiku-latest","async":true}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/ai/config", bytes.NewReader(body))
	handler.UpdateAIConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected ai config update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.AI.Provider != "anthropic" || cfg.AI.APIKey != "existing-secret" {
		t.Fatalf("unexpected saved AI config: %+v", cfg.AI)
	}

	var response struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Data["provider"] != "anthropic" {
		t.Fatalf("expected provider in response, got %+v", response.Data)
	}
	if _, ok := response.Data["api_key_header"]; ok {
		t.Fatalf("api_key_header should not be returned to the Web UI: %+v", response.Data)
	}
	if _, ok := response.Data["api_key"]; ok {
		t.Fatalf("api_key should not be returned to the Web UI: %+v", response.Data)
	}
}

func TestAnalyzeEventsAppliesTimeRange(t *testing.T) {
	start := time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	sink := &recordingAISink{
		items: []storage.LogEntry{{
			ID:        "event-1",
			Timestamp: start.Add(5 * time.Minute),
			Action:    "block",
			Category:  "sqli",
			URI:       "/?id=1",
		}},
	}
	cfg := config.Default()
	handler := New(Options{Config: &cfg, Sink: sink})
	raw, _ := json.Marshal(map[string]any{
		"limit": 20,
		"start": start.Format(time.RFC3339Nano),
		"end":   end.Format(time.RFC3339Nano),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/events/analyze", bytes.NewReader(raw))
	handler.AnalyzeEvents(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected event analysis ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !sink.filter.StartTime.Equal(start) || !sink.filter.EndTime.Equal(end) || sink.filter.Limit != 20 {
		t.Fatalf("unexpected log filter: %+v", sink.filter)
	}
}

func TestAnalyzeEventsRejectsInvalidTimeRange(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})
	body := []byte(`{"start":"2026-06-08T11:00:00Z","end":"2026-06-08T10:00:00Z"}`)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/events/analyze", bytes.NewReader(body))
	handler.AnalyzeEvents(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad time range, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAnalyzeLogReferenceLoadsStoredEvent(t *testing.T) {
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:         "log-1",
		TraceID:    "trace-real",
		Action:     "block",
		Category:   "sqli",
		Severity:   "high",
		Method:     http.MethodGet,
		URI:        "/search?q=1",
		ClientIP:   "203.0.113.9",
		DetectorID: "semantic.sqli",
	}}}
	handler := New(Options{Config: ptrConfig(config.Default()), Sink: sink})
	body := []byte(`{"reference":"trace-real","event":{"id":"fake","trace_id":"trace-real","category":"xss","severity":"low","uri":"/fake"}}`)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/analyze", bytes.NewReader(body))
	handler.AnalyzeLog(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected analysis ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := response.Data["risk"]; got != "high" {
		t.Fatalf("expected stored event risk, got %v response=%+v", got, response.Data)
	}
	if got := response.Data["summary"]; !strings.Contains(got.(string), "sqli") || strings.Contains(got.(string), "xss") {
		t.Fatalf("expected summary to use stored event, got %q", got)
	}
	if len(sink.filters) == 0 || sink.filters[0].TraceID != "trace-real" {
		t.Fatalf("expected first query by trace reference, filters=%+v", sink.filters)
	}
}

func TestAnalyzeLogReferenceNotFound(t *testing.T) {
	sink := &filteringAISink{}
	handler := New(Options{Config: ptrConfig(config.Default()), Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/analyze", bytes.NewReader([]byte(`{"reference":"missing-trace"}`)))
	handler.AnalyzeLog(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected log not found, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAnalyzeLogLegacyPayloadPrefersStoredEvent(t *testing.T) {
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:       "stored-id",
		TraceID:  "trace-from-legacy",
		Action:   "block",
		Category: "rce",
		Severity: "critical",
		URI:      "/api/run",
	}}}
	handler := New(Options{Config: ptrConfig(config.Default()), Sink: sink})
	body := []byte(`{"id":"client-id","trace_id":"trace-from-legacy","action":"block","category":"xss","severity":"low","uri":"/client"}`)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/analyze", bytes.NewReader(body))
	handler.AnalyzeLog(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected analysis ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := response.Data["risk"]; got != "critical" {
		t.Fatalf("expected stored critical risk, got %v response=%+v", got, response.Data)
	}
}

type recordingAISink struct {
	items  []storage.LogEntry
	filter storage.LogFilter
}

func (s *recordingAISink) Write(context.Context, *storage.LogEntry) error {
	return nil
}

func (s *recordingAISink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.filter = filter
	return s.items, int64(len(s.items)), nil
}

func (s *recordingAISink) Flush(context.Context) error {
	return nil
}

func (s *recordingAISink) Close() error {
	return nil
}

type filteringAISink struct {
	items   []storage.LogEntry
	filters []storage.LogFilter
}

func (s *filteringAISink) Write(context.Context, *storage.LogEntry) error {
	return nil
}

func (s *filteringAISink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.filters = append(s.filters, filter)
	out := make([]storage.LogEntry, 0, len(s.items))
	for _, entry := range s.items {
		if filter.TraceID != "" && entry.TraceID != filter.TraceID {
			continue
		}
		out = append(out, entry)
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, int64(len(out)), nil
}

func (s *filteringAISink) Flush(context.Context) error {
	return nil
}

func (s *filteringAISink) Close() error {
	return nil
}

func ptrConfig(cfg config.Config) *config.Config {
	return &cfg
}
