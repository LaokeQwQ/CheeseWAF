package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
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

func TestAIModelsCanUseUnsavedOpenAIConfig(t *testing.T) {
	var gotPath string
	var gotAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"deepseek-chat","owned_by":"test"},{"id":"gpt-4o-mini","owned_by":"openai"}]}`))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.AI.Enabled = false
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://saved.invalid/v1"
	cfg.AI.APIKey = "saved-key"
	handler := New(Options{Config: &cfg})

	raw, _ := json.Marshal(map[string]any{
		"provider":               "openai",
		"api_base":               upstream.URL,
		"api_key":                "typed-key",
		"allow_private_api_base": true,
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/models", bytes.NewReader(raw))
	handler.AIModels(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected models ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if gotPath != "/models" || gotAuthorization != "Bearer typed-key" {
		t.Fatalf("expected unsaved config to be used, path=%q authorization=%q", gotPath, gotAuthorization)
	}
	if cfg.AI.APIBase != "https://saved.invalid/v1" || cfg.AI.APIKey != "saved-key" || cfg.AI.Enabled {
		t.Fatalf("AIModels should not persist temporary config: %+v", cfg.AI)
	}
	var response struct {
		Data struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Data.Total != 2 || response.Data.Items[0].ID != "deepseek-chat" {
		t.Fatalf("unexpected model response: %+v", response.Data)
	}
}

func TestAITestConnectionCanUseUnsavedOpenAIConfig(t *testing.T) {
	var gotPath string
	var gotAuthorization string
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		gotBody = raw.String()
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://saved.invalid/v1"
	cfg.AI.APIKey = "saved-key"
	cfg.AI.Model = "saved-model"
	handler := New(Options{Config: &cfg})

	raw, _ := json.Marshal(map[string]any{
		"target":                 "assistant",
		"provider":               "openai",
		"api_base":               upstream.URL,
		"api_key":                "typed-key",
		"model":                  "typed-model",
		"allow_private_api_base": true,
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/test", bytes.NewReader(raw))
	handler.TestAIConnection(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected test connection ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if gotPath != "/chat/completions" || gotAuthorization != "Bearer typed-key" || !strings.Contains(gotBody, "typed-model") {
		t.Fatalf("expected unsaved config to be used, path=%q authorization=%q body=%s", gotPath, gotAuthorization, gotBody)
	}
	if cfg.AI.APIBase != "https://saved.invalid/v1" || cfg.AI.APIKey != "saved-key" || cfg.AI.Model != "saved-model" {
		t.Fatalf("TestAIConnection should not persist temporary config: %+v", cfg.AI)
	}
}

func TestAITestConnectionRejectsMissingAPIKeyBeforeProviderCall(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = upstream.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = ""
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg})

	raw, _ := json.Marshal(map[string]any{
		"target":                 "assistant",
		"provider":               "openai",
		"api_base":               upstream.URL,
		"api_key":                "",
		"model":                  "test-model",
		"allow_private_api_base": true,
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/test", bytes.NewReader(raw))
	handler.TestAIConnection(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected missing key to be rejected before provider call, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if called {
		t.Fatalf("provider should not be called when api key is missing")
	}
	if !strings.Contains(recorder.Body.String(), "AI_KEY_REQUIRED") {
		t.Fatalf("expected AI_KEY_REQUIRED, body=%s", recorder.Body.String())
	}
}

func TestAIModelsRejectsPrivateAPIBaseByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.AI.APIKey = "saved-key"
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/models", bytes.NewReader([]byte(`{"provider":"openai","api_base":"http://127.0.0.1:11434/v1","api_key":"typed-key"}`)))
	handler.AIModels(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected private api base to be rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "AI_API_BASE_INVALID") {
		t.Fatalf("expected invalid api base code, body=%s", recorder.Body.String())
	}
}

func TestUpdateAIConfigRejectsPrivateAPIBaseByDefault(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	body := []byte(`{"enabled":true,"provider":"openai","api_base":"http://127.0.0.1:11434/v1","api_key":"typed-key","model":"local-model","async":true}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/ai/config", bytes.NewReader(body))
	handler.UpdateAIConfig(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected private api base config to be rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "AI_API_BASE_INVALID") {
		t.Fatalf("expected invalid api base code, body=%s", recorder.Body.String())
	}
}

func TestUpdateAIConfigAllowsPrivateAPIBaseWhenExplicit(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	body := []byte(`{"enabled":true,"provider":"openai","api_base":"http://127.0.0.1:11434/v1","api_key":"typed-key","model":"local-model","async":true,"allow_private_api_base":true}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/ai/config", bytes.NewReader(body))
	handler.UpdateAIConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected explicit private api base config ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !cfg.AI.AllowPrivateAPIBase || cfg.AI.APIBase != "http://127.0.0.1:11434/v1" {
		t.Fatalf("expected private api base to be saved only after explicit opt-in, got %+v", cfg.AI)
	}
}

func TestAIModelsRejectsInvalidAPIBase(t *testing.T) {
	cfg := config.Default()
	cfg.AI.APIKey = "saved-key"
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/models", bytes.NewReader([]byte(`{"provider":"openai","api_base":"file:///tmp/models","api_key":"typed-key"}`)))
	handler.AIModels(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid api base to be rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "AI_API_BASE_INVALID") {
		t.Fatalf("expected invalid api base code, body=%s", recorder.Body.String())
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

func TestAnalyzeLogStreamEmitsProviderTraceAndDone(t *testing.T) {
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:        "event-stream-analysis",
		TraceID:   "trace-stream-analysis",
		Action:    "block",
		Category:  "sqli",
		Severity:  "high",
		Method:    http.MethodGet,
		URI:       "/search?q=1",
		ClientIP:  "203.0.113.9",
		Timestamp: time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"Checking\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\" \"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"evidence\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"SQLi\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":17,\"completion_tokens\":4,\"total_tokens\":21}}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = server.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = "test-secret"
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/analyze/stream", bytes.NewReader([]byte(`{"reference":"trace-stream-analysis","language":"zh-CN"}`)))
	handler.AnalyzeLogStream(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected stream ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("expected SSE content type, got %q", got)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"event: trace",
		`"type":"stream_open"`,
		`"type":"provider_response_start"`,
		`"type":"reasoning_delta","message":" "`,
		`"type":"content_delta"`,
		"event: done",
		`"summary":"SQLi"`,
		`"reasoning_summary":"Checking evidence"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %q in body:\n%s", want, body)
		}
	}
}

func TestAnalyzeLogStreamFallsBackToDoneWhenProviderFails(t *testing.T) {
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:        "event-stream-provider-fail",
		TraceID:   "trace-stream-provider-fail",
		Action:    "block",
		Category:  "xss",
		Severity:  "medium",
		Method:    http.MethodPost,
		URI:       "/comment",
		ClientIP:  "203.0.113.20",
		Timestamp: time.Date(2026, 6, 11, 10, 5, 0, 0, time.UTC),
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad api key", http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = server.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = "bad-secret"
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/analyze/stream", bytes.NewReader([]byte(`{"reference":"trace-stream-provider-fail","language":"en-US"}`)))
	handler.AnalyzeLogStream(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected stream fallback ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"event: trace",
		"event: done",
		`"log_id":"event-stream-provider-fail"`,
		`"ai_used":false`,
		"Provider error",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("fallback stream missing %q in body:\n%s", want, body)
		}
	}
	if strings.Contains(body, "event: error") {
		t.Fatalf("provider failure should be returned as heuristic done result, got body:\n%s", body)
	}
}

func TestAIAssistantReturnsRealToolExecutions(t *testing.T) {
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:        "event-1",
		TraceID:   "trace-1",
		Timestamp: now,
		Action:    "block",
		Category:  "sqli",
		Severity:  "high",
		ClientIP:  "203.0.113.10",
		URI:       "/search?q=1",
	}}}
	handler := New(Options{Config: ptrConfig(config.Default()), Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/assistant", bytes.NewReader([]byte(`{"message":"请读取系统状态和最近安全事件","limit":10}`)))
	handler.AIAssistant(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assistant ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			ToolExecutions []struct {
				Name        string `json:"name"`
				Sensitivity string `json:"sensitivity"`
				Result      *struct {
					Success bool   `json:"success"`
					Output  string `json:"output"`
				} `json:"result"`
			} `json:"tool_executions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data.ToolExecutions) != 2 {
		t.Fatalf("expected system and event tools, got %+v", response.Data.ToolExecutions)
	}
	seenEvents := false
	for _, call := range response.Data.ToolExecutions {
		if call.Sensitivity != "read_only" || call.Result == nil || !call.Result.Success {
			t.Fatalf("expected read-only successful tool call, got %+v", call)
		}
		if call.Name == "recent_security_events" && strings.Contains(call.Result.Output, "event-1") {
			seenEvents = true
		}
	}
	if !seenEvents {
		t.Fatalf("expected recent events tool output to include stored event: %+v", response.Data.ToolExecutions)
	}
}

func TestAIAssistantUsesKnowledgeBaseForProductQuestions(t *testing.T) {
	cfg := config.Default()
	cfg.AI.Knowledge.Enabled = true
	cfg.AI.Knowledge.Builtin = true
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/assistant", bytes.NewReader([]byte(`{"message":"How do self-learning rules reduce false positives?","limit":10}`)))
	handler.AIAssistant(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assistant ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			ToolExecutions []struct {
				Name   string `json:"name"`
				Result *struct {
					Output string `json:"output"`
				} `json:"result"`
			} `json:"tool_executions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, call := range response.Data.ToolExecutions {
		if call.Name == "knowledge_base" && call.Result != nil && strings.Contains(call.Result.Output, "ai-self-learning") {
			return
		}
	}
	t.Fatalf("expected knowledge_base tool execution, got %+v", response.Data.ToolExecutions)
}

func TestAIAssistantFetchesEventsOnlyAfterToolRequest(t *testing.T) {
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:        "event-1",
		TraceID:   "trace-1",
		Timestamp: now,
		Action:    "block",
		Category:  "sqli",
		Severity:  "high",
		ClientIP:  "203.0.113.10",
		URI:       "/search?q=1",
	}}}
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		bodies = append(bodies, raw.String())
		w.Header().Set("Content-Type", "application/json")
		if len(bodies) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"tool_calls\":[{\"name\":\"recent_security_events\",\"args\":{\"limit\":5}}]}"}}],"usage":{"prompt_tokens":31,"completion_tokens":9,"total_tokens":40}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"已读取工具结果：最近 1 条安全事件，1 条已拦截。"}}],"usage":{"prompt_tokens":41,"completion_tokens":12,"total_tokens":53}}`))
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = server.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = "test-secret"
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/assistant", bytes.NewReader([]byte(`{"message":"请分析最近安全事件","language":"zh-CN","limit":10}`)))
	handler.AIAssistant(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assistant ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(bodies) != 2 {
		t.Fatalf("expected planning and final AI calls, got %d bodies=%+v", len(bodies), bodies)
	}
	if strings.Contains(bodies[0], "event-1") || strings.Contains(bodies[0], "runtime_json") || strings.Contains(bodies[0], "event_json") {
		t.Fatalf("planning request should not include runtime/event data: %s", bodies[0])
	}
	if !strings.Contains(bodies[0], "使用{%Language}") || !strings.Contains(bodies[0], "Simplified Chinese") {
		t.Fatalf("planning request missing language directive: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], "event-1") || !strings.Contains(bodies[1], "tool_results") {
		t.Fatalf("final request should include tool results only after execution: %s", bodies[1])
	}
	var response struct {
		Data struct {
			Answer         string `json:"answer"`
			AIUsed         bool   `json:"ai_used"`
			InputTokens    int    `json:"input_tokens"`
			OutputTokens   int    `json:"output_tokens"`
			ToolExecutions []struct {
				Name string `json:"name"`
			} `json:"tool_executions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Data.AIUsed || !strings.Contains(response.Data.Answer, "最近 1 条安全事件") || len(response.Data.ToolExecutions) != 1 {
		t.Fatalf("unexpected assistant response: %+v", response.Data)
	}
	if strings.Contains(response.Data.Answer, "工具结果") {
		t.Fatalf("assistant final answer leaked tool process: %s", response.Data.Answer)
	}
	if response.Data.InputTokens != 72 || response.Data.OutputTokens != 21 {
		t.Fatalf("expected aggregated token usage, got %+v", response.Data)
	}
}

func TestAIAssistantAllowsNonStreamingResponsePastServerWriteTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK after delay"}}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}}`))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = upstream.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = "test-secret"
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg})
	server := httptest.NewUnstartedServer(http.HandlerFunc(handler.AIAssistant))
	server.Config.WriteTimeout = 80 * time.Millisecond
	server.Start()
	defer server.Close()

	client := server.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Post(server.URL, "application/json", strings.NewReader(`{"message":"hello","language":"en","limit":10}`))
	if err != nil {
		t.Fatalf("post assistant request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read assistant response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected assistant ok, status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "OK after delay") {
		t.Fatalf("expected delayed AI answer, body=%s", body)
	}
}

func TestProviderStreamEmitterEmitsRepeatedWaitingProgress(t *testing.T) {
	oldSlowAfter := providerFirstEventSlowAfter
	oldProgressInterval := providerWaitingProgressInterval
	providerFirstEventSlowAfter = 5 * time.Millisecond
	providerWaitingProgressInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		providerFirstEventSlowAfter = oldSlowAfter
		providerWaitingProgressInterval = oldProgressInterval
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan ai.AssistantTraceEvent, 4)
	_, stop := providerStreamEmitter(ctx, "zh-CN", "planning", func(event ai.AssistantTraceEvent) {
		events <- event
	})
	defer stop()

	want := []string{"provider_first_event_slow", "provider_waiting_progress"}
	got := make([]string, 0, len(want))
	deadline := time.After(100 * time.Millisecond)
	for len(got) < len(want) {
		select {
		case event := <-events:
			if event.Type == "provider_first_event_slow" || event.Type == "provider_waiting_progress" {
				got = append(got, event.Type)
			}
		case <-deadline:
			t.Fatalf("expected repeated provider waiting progress %v, got %v", want, got)
		}
	}
	for index, wantType := range want {
		if got[index] != wantType {
			t.Fatalf("event %d = %q, want %q; all=%v", index, got[index], wantType, got)
		}
	}
}

func TestAIAssistantStreamEmitsToolTraceAndDone(t *testing.T) {
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:        "event-stream-1",
		TraceID:   "trace-stream-1",
		Timestamp: now,
		Action:    "block",
		Category:  "sqli",
		Severity:  "high",
		ClientIP:  "203.0.113.10",
		URI:       "/search?q=1",
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if strings.Contains(raw.String(), `"tools"`) {
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"recent_security_events\",\"arguments\":\"{\\\"limit\\\":5}\"}}]}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":31,\"completion_tokens\":5,\"total_tokens\":36}}\n\n")
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"已基于工具 observation 完成分析。\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":41,\"completion_tokens\":8,\"total_tokens\":49}}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = server.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = "test-secret"
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/assistant/stream", bytes.NewReader([]byte(`{"message":"请分析最近安全事件","language":"zh-CN","limit":10}`)))
	handler.AIAssistantStream(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assistant stream ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"event: trace",
		`"type":"planning_start"`,
		`"type":"tool_call"`,
		`"type":"tool_result"`,
		"event-stream-1",
		"event: done",
		`"answer":"已完成分析。"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %q in body:\n%s", want, body)
		}
	}
}

func TestAIAssistantStreamEmitsProviderReasoningBeforeDone(t *testing.T) {
	sink := &filteringAISink{items: []storage.LogEntry{{
		ID:        "event-stream-reasoning",
		TraceID:   "trace-stream-reasoning",
		Timestamp: time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
		Action:    "block",
		Category:  "xss",
		Severity:  "high",
		ClientIP:  "203.0.113.42",
		URI:       "/login",
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if strings.Contains(raw.String(), `"tools"`) {
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"先读取最近事件\"}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"recent_security_events\",\"arguments\":\"{\\\"limit\\\":5}\"}}]}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":31,\"completion_tokens\":5,\"total_tokens\":36}}\n\n")
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"基于 observation 汇总\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"已基于真实工具 observation 完成分析。\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":41,\"completion_tokens\":8,\"total_tokens\":49}}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = server.URL
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.APIKey = "test-secret"
	cfg.AI.Model = "test-model"
	handler := New(Options{Config: &cfg, Sink: sink})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/assistant/stream", bytes.NewReader([]byte(`{"message":"请分析最近安全事件","language":"zh-CN","limit":10}`)))
	handler.AIAssistantStream(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assistant stream ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	reasoningIndex := strings.Index(body, `"type":"reasoning_delta"`)
	doneIndex := strings.Index(body, "event: done")
	if reasoningIndex < 0 || doneIndex < 0 || reasoningIndex > doneIndex {
		t.Fatalf("expected reasoning delta before done, reasoning=%d done=%d body:\n%s", reasoningIndex, doneIndex, body)
	}
	for _, want := range []string{
		`"type":"provider_response_start"`,
		`"type":"tool_call_delta"`,
		`"type":"content_delta"`,
		`"answer":"已完成分析。"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %q in body:\n%s", want, body)
		}
	}
}

func TestAIAssistantCreatesApprovalForConfigIntent(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.Bot.Secret = "test-bot-secret-value"
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ai/assistant", bytes.NewReader([]byte(`{"message":"请帮我开启滑块验证码","limit":10}`)))
	handler.AIAssistant(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected assistant ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			ToolExecutions []struct {
				Name     string `json:"name"`
				Approval *struct {
					ID       string         `json:"id"`
					ToolName string         `json:"tool_name"`
					Args     map[string]any `json:"args"`
					Diff     string         `json:"diff"`
					Status   string         `json:"status"`
				} `json:"approval"`
			} `json:"tool_executions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data.ToolExecutions) != 1 || response.Data.ToolExecutions[0].Approval == nil {
		t.Fatalf("expected one pending approval, got %+v", response.Data.ToolExecutions)
	}
	approval := response.Data.ToolExecutions[0].Approval
	if approval.ToolName != "set_bot_challenge" || approval.Status != "pending" || approval.Args["captcha_type"] != "slider" {
		t.Fatalf("unexpected approval: %+v", approval)
	}
	if strings.Contains(approval.Diff, cfg.Protection.Bot.Secret) || !strings.Contains(approval.Diff, "[redacted]") {
		t.Fatalf("approval diff should redact bot secret, got %s", approval.Diff)
	}
	if cfg.Protection.Bot.CAPTCHAType == "slider" && cfg.Protection.Bot.CAPTCHA {
		t.Fatal("bot captcha changed before approval")
	}
}

func TestAIToolApprovalExecutesOnceAndReloadsProtection(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var reloaded bool
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(config.ProtectionConfig) error {
			reloaded = true
			return nil
		},
	})
	router := chi.NewRouter()
	router.Post("/execute", handler.ExecuteAITool)
	router.Post("/approvals/{id}/approve", handler.ApproveAIApproval)

	args := `{"area":"bot_cc","level":"high"}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader([]byte(`{"name":"set_protection_level","args":`+args+`}`)))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected approval request ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var first struct {
		Data struct {
			Approval *struct {
				ID     string `json:"id"`
				Status string `json:"status"`
				Diff   string `json:"diff"`
			} `json:"approval"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if first.Data.Approval == nil || first.Data.Approval.ID == "" || !strings.Contains(first.Data.Approval.Diff, `"bot_cc": "high"`) {
		t.Fatalf("expected pending approval with diff, got %+v", first.Data.Approval)
	}
	if cfg.Protection.Policy.BotCC == "high" {
		t.Fatal("policy changed before approval")
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/approvals/"+first.Data.Approval.ID+"/approve", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected approve ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader([]byte(`{"name":"set_protection_level","approval_id":"`+first.Data.Approval.ID+`","args":`+args+`}`)))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected approved execute ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.Protection.Policy.BotCC != "high" || !reloaded {
		t.Fatalf("expected policy update and reload, policy=%+v reloaded=%v", cfg.Protection.Policy, reloaded)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader([]byte(`{"name":"set_protection_level","approval_id":"`+first.Data.Approval.ID+`","args":`+args+`}`)))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected approval reuse to fail, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAIToolApprovalCannotWriteDuringClusterProtectionMode(t *testing.T) {
	cfg := minimumHAHandlerConfig()
	handler := New(Options{Config: &cfg})
	router := chi.NewRouter()
	router.Post("/execute", handler.ExecuteAITool)
	router.Post("/approvals/{id}/approve", handler.ApproveAIApproval)

	args := `{"area":"bot_cc","level":"high"}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader([]byte(`{"name":"set_protection_level","args":`+args+`}`)))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected approval request ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var first struct {
		Data struct {
			Approval *struct {
				ID string `json:"id"`
			} `json:"approval"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if first.Data.Approval == nil || first.Data.Approval.ID == "" {
		t.Fatalf("expected pending approval, got %+v", first.Data.Approval)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/approvals/"+first.Data.Approval.ID+"/approve", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected approve ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader([]byte(`{"name":"set_protection_level","approval_id":"`+first.Data.Approval.ID+`","args":`+args+`}`)))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected protected execute to fail, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.Protection.Policy.BotCC == "high" {
		t.Fatalf("policy changed despite cluster protection mode: %+v", cfg.Protection.Policy)
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
