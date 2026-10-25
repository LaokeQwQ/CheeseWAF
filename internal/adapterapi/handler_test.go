package adapterapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type fakeInspector struct {
	decision Decision
	err      error
	got      Request
}

func (f *fakeInspector) InspectAdapter(_ context.Context, request Request) (Decision, error) {
	f.got = request
	return f.decision, f.err
}

type fakeSink struct {
	entries []*storage.LogEntry
}

func (f *fakeSink) Write(_ context.Context, entry *storage.LogEntry) error {
	f.entries = append(f.entries, entry)
	return nil
}
func (f *fakeSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}
func (f *fakeSink) Flush(context.Context) error { return nil }
func (f *fakeSink) Close() error                { return nil }

func newTestHandler(t *testing.T, inspector Inspector, token string, sink storage.LogSink) *Handler {
	t.Helper()
	handler, err := NewHandler(inspector, token, sink)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestInspectReturnsInspectorDecision(t *testing.T) {
	inspector := &fakeInspector{decision: Decision{Action: ActionBlock, StatusCode: 403, Reason: "sqli"}}
	handler := newTestHandler(t, inspector, "", &fakeSink{})
	body, _ := json.Marshal(Request{
		ContractVersion: Version,
		Source:          SourceGeneric,
		Method:          http.MethodGet,
		Path:            "/search",
		Authority:       "app.example",
		BodyState:       BodyStateAbsent,
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/adapter/inspect", bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var decision Decision
	if err := json.NewDecoder(recorder.Body).Decode(&decision); err != nil {
		t.Fatal(err)
	}
	if decision.Action != ActionBlock || decision.StatusCode != 403 {
		t.Fatalf("decision = %+v", decision)
	}
	if inspector.got.Path != "/search" {
		t.Fatalf("inspector path = %q", inspector.got.Path)
	}
}

func TestInspectRequiresTokenForNonLoopback(t *testing.T) {
	inspector := &fakeInspector{decision: Decision{Action: ActionAllow}}
	handler := newTestHandler(t, inspector, "secret", &fakeSink{})
	body, _ := json.Marshal(Request{Method: http.MethodGet, Path: "/", BodyState: BodyStateAbsent})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/adapter/inspect", bytes.NewReader(body))
	request.RemoteAddr = "203.0.113.10:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/adapter/inspect", bytes.NewReader(body))
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("Authorization", "Bearer secret")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestTelemetryWritesLogEntry(t *testing.T) {
	sink := &fakeSink{}
	handler := newTestHandler(t, &fakeInspector{}, "", sink)
	body, _ := json.Marshal(TelemetryEvent{
		ContractVersion: Version,
		RequestID:       "req-1",
		Source:          SourceNginxAuth,
		Action:          ActionBlock,
		Path:            "/admin",
		StatusCode:      403,
		LatencyNanos:    1200,
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/adapter/telemetry", bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if len(sink.entries) != 1 {
		t.Fatalf("entries = %d", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.TraceID != "req-1" || entry.Action != "block" || entry.URI != "/admin" || entry.StatusCode != 403 {
		t.Fatalf("entry = %+v", entry)
	}
	if entry.Metadata["source"] != string(SourceNginxAuth) {
		t.Fatalf("metadata = %+v", entry.Metadata)
	}
}

func TestHealth(t *testing.T) {
	handler := newTestHandler(t, &fakeInspector{}, "", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}
