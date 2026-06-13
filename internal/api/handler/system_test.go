package handler

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestPreviewBlockPageConfigRendersRuntimeHTMLWithoutPersisting(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls int
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls++
			return nil
		},
	})
	payload := config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body><main>event={{.EventID}} status={{.Status}} type={{.AttackType}}</main></body></html>`,
	}
	raw, _ := json.Marshal(payload)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/block-pages/preview", bytes.NewReader(raw))
	request.RemoteAddr = "203.0.113.10:49152"

	handler.PreviewBlockPageConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected preview ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data struct {
			HTML    string `json:"html"`
			EventID string `json:"event_id"`
			TraceID string `json:"trace_id"`
			Status  int    `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if body.Data.EventID == "" || body.Data.TraceID != body.Data.EventID {
		t.Fatalf("expected preview trace/event ids, got %+v", body.Data)
	}
	if body.Data.Status != http.StatusForbidden || !strings.Contains(body.Data.HTML, body.Data.EventID) || strings.Contains(body.Data.HTML, "{{.EventID}}") {
		t.Fatalf("preview did not render runtime data: %+v", body.Data)
	}
	if calls != 0 {
		t.Fatalf("preview must not trigger hot reload, calls=%d", calls)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if loaded.BlockPage.CustomEnabled {
		t.Fatalf("preview must not persist block page config: %+v", loaded.BlockPage)
	}
}

func TestUploadAndDeleteCustomBlockPagePersistsAndNotifies(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls []config.BlockPageConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls = append(calls, next)
			return nil
		},
	})

	customHTML := `<html><body><main data-event="{{.EventID}}">blocked {{.TraceID}}</main></body></html>`
	uploadRecorder := httptest.NewRecorder()
	uploadRequest := multipartBlockPageUploadRequest(t, customHTML, "custom-block.html", "minimal")
	handler.UploadBlockPageHTML(uploadRecorder, uploadRequest)
	if uploadRecorder.Code != http.StatusOK {
		t.Fatalf("expected upload ok, code=%d body=%s", uploadRecorder.Code, uploadRecorder.Body.String())
	}
	if len(calls) != 1 || !calls[0].CustomEnabled || calls[0].CustomHTML != customHTML {
		t.Fatalf("expected upload reload callback with custom html, calls=%+v", calls)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config after upload: %v", err)
	}
	if !loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != customHTML {
		t.Fatalf("uploaded block page was not persisted: %+v", loaded.BlockPage)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/block-pages/custom", nil)
	handler.DeleteCustomBlockPage(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("expected delete custom ok, code=%d body=%s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if len(calls) != 2 || calls[1].CustomEnabled || calls[1].CustomHTML != "" {
		t.Fatalf("expected delete reload callback to clear custom html, calls=%+v", calls)
	}
	loaded, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config after delete: %v", err)
	}
	if loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != "" {
		t.Fatalf("custom block page was not cleared from persisted config: %+v", loaded.BlockPage)
	}
}

func TestUploadCustomBlockPageRejectsNonHTMLUpload(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	recorder := httptest.NewRecorder()
	request := multipartBlockPageUploadRequest(t, `not html`, "notes.txt", "minimal")
	handler.UploadBlockPageHTML(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "BLOCK_PAGE_UPLOAD_NOT_HTML") {
		t.Fatalf("expected non-html upload rejection, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != "" {
		t.Fatalf("non-html upload mutated config: %+v", loaded.BlockPage)
	}
}

func TestUploadCustomBlockPageRejectsInvalidTemplateWithoutMutatingConfig(t *testing.T) {
	cfg := config.Default()
	cfg.BlockPage.CustomEnabled = true
	cfg.BlockPage.CustomHTML = `<html><body>{{.TraceID}}</body></html>`
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls int
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls++
			return nil
		},
	})

	recorder := httptest.NewRecorder()
	request := multipartBlockPageUploadRequest(t, `<html><body>{{if}}</body></html>`, "bad.html", "minimal")
	handler.UploadBlockPageHTML(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "BLOCK_PAGE_TEMPLATE_INVALID") {
		t.Fatalf("expected invalid template rejection, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls != 0 {
		t.Fatalf("invalid upload should not notify hot reload, calls=%d", calls)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != `<html><body>{{.TraceID}}</body></html>` {
		t.Fatalf("invalid upload mutated persisted config: %+v", loaded.BlockPage)
	}
}

func multipartBlockPageUploadRequest(t *testing.T, html, filename, templateID string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if templateID != "" {
		if err := writer.WriteField("template_id", templateID); err != nil {
			t.Fatalf("write template field: %v", err)
		}
	}
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create upload field: %v", err)
	}
	if _, err := part.Write([]byte(html)); err != nil {
		t.Fatalf("write upload body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/block-pages/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func TestWriteErrorIncludesTraceID(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, http.StatusBadRequest, "BAD_REQUEST", "bad")
	if recorder.Header().Get("X-CheeseWAF-Trace-ID") == "" {
		t.Fatal("expected trace id response header")
	}
	if recorder.Header().Get("X-CheeseWAF-Event-ID") == "" {
		t.Fatal("expected event id response header")
	}
	if recorder.Header().Get("X-CheeseWAF-Event-ID") != recorder.Header().Get("X-CheeseWAF-Trace-ID") {
		t.Fatalf("event id should match trace id header, event=%q trace=%q", recorder.Header().Get("X-CheeseWAF-Event-ID"), recorder.Header().Get("X-CheeseWAF-Trace-ID"))
	}
	var body struct {
		Error struct {
			TraceID string `json:"trace_id"`
			EventID string `json:"event_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.TraceID == "" || body.Error.TraceID != recorder.Header().Get("X-CheeseWAF-Trace-ID") {
		t.Fatalf("trace id mismatch header=%q body=%q", recorder.Header().Get("X-CheeseWAF-Trace-ID"), body.Error.TraceID)
	}
	if body.Error.EventID == "" || body.Error.EventID != recorder.Header().Get("X-CheeseWAF-Event-ID") {
		t.Fatalf("event id mismatch header=%q body=%q", recorder.Header().Get("X-CheeseWAF-Event-ID"), body.Error.EventID)
	}
}
