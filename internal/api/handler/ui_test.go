package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestReportUIErrorWritesTraceableLogEntry(t *testing.T) {
	sink := &uiReportSink{}
	handler := New(Options{Sink: sink})
	raw, _ := json.Marshal(map[string]any{
		"trace_id":        "cw-ui-test123",
		"name":            "TypeError",
		"message":         "cannot read properties of undefined",
		"stack":           "TypeError: cannot read properties of undefined",
		"component_stack": "at DashboardPage",
		"path":            "/ip?tab=intel",
		"user_agent":      "Mozilla/5.0",
		"language":        "zh-CN",
		"viewport": map[string]any{
			"width":  1440,
			"height": 900,
		},
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ui/errors", bytes.NewReader(raw))
	handler.ReportUIError(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected UI error report ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-CheeseWAF-Trace-ID") != "cw-ui-test123" {
		t.Fatalf("expected response trace header to match UI trace, got %q", recorder.Header().Get("X-CheeseWAF-Trace-ID"))
	}
	if len(sink.entries) != 1 {
		t.Fatalf("expected one log entry, got %d", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.ID != "cw-ui-test123" || entry.TraceID != "cw-ui-test123" {
		t.Fatalf("trace id mismatch: %#v", entry)
	}
	if entry.Action != "error" || entry.Category != "ui_error" || entry.DetectorID != "ui.error_boundary" {
		t.Fatalf("unexpected UI error log classification: %#v", entry)
	}
	if entry.SiteID != "admin-console" || entry.Method != "UI" || entry.URI != "/ip?tab=intel" {
		t.Fatalf("unexpected UI error location fields: %#v", entry)
	}
	if entry.Metadata["component_stack"] != "at DashboardPage" || entry.Metadata["language"] != "zh-CN" || entry.Metadata["viewport_width"] != 1440 {
		t.Fatalf("missing UI diagnostic metadata: %#v", entry.Metadata)
	}
}

func TestReportUIErrorNormalizesBadTraceID(t *testing.T) {
	sink := &uiReportSink{}
	handler := New(Options{Sink: sink})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ui/errors", bytes.NewReader([]byte(`{"trace_id":"bad trace id","message":"boom"}`)))

	handler.ReportUIError(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected UI error report ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(sink.entries) != 1 {
		t.Fatalf("expected one log entry, got %d", len(sink.entries))
	}
	if sink.entries[0].TraceID == "bad trace id" || sink.entries[0].TraceID == "" {
		t.Fatalf("expected invalid UI trace id to be replaced, got %q", sink.entries[0].TraceID)
	}
}

func TestReportUIErrorKeepsTraceIDWhenSinkFails(t *testing.T) {
	handler := New(Options{Sink: uiReportFailingSink{}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ui/errors", bytes.NewReader([]byte(`{"trace_id":"cw-ui-fail","message":"boom"}`)))

	handler.ReportUIError(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected sink failure to return 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-CheeseWAF-Trace-ID") != "cw-ui-fail" {
		t.Fatalf("expected sink failure response to keep UI trace id, got %q", recorder.Header().Get("X-CheeseWAF-Trace-ID"))
	}
	var envelope struct {
		Error struct {
			TraceID string `json:"trace_id"`
		} `json:"error"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if envelope.Error.TraceID != "cw-ui-fail" {
		t.Fatalf("expected JSON error to keep UI trace id, got %q", envelope.Error.TraceID)
	}
}

type uiReportSink struct {
	entries []*storage.LogEntry
}

func (s *uiReportSink) Write(_ context.Context, entry *storage.LogEntry) error {
	s.entries = append(s.entries, entry)
	return nil
}

func (s *uiReportSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}

func (s *uiReportSink) Flush(context.Context) error {
	return nil
}

func (s *uiReportSink) Close() error {
	return nil
}

type uiReportFailingSink struct{}

func (uiReportFailingSink) Write(context.Context, *storage.LogEntry) error {
	return errors.New("sink unavailable")
}

func (uiReportFailingSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}

func (uiReportFailingSink) Flush(context.Context) error {
	return nil
}

func (uiReportFailingSink) Close() error {
	return nil
}
