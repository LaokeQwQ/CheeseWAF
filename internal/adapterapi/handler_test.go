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

func TestInspectJSONLimitAllowsBase64Body(t *testing.T) {
	minimum := int64(maxInspectBodyBytes)*4/3 + 1024
	if int64(maxInspectJSONBytes) < minimum {
		t.Fatalf("inspection JSON limit %d cannot carry a base64 %d-byte body (needs >= %d)", maxInspectJSONBytes, maxInspectBodyBytes, minimum)
	}
}

func TestSetTokenRotatesCredentialWithoutRestart(t *testing.T) {
	inspector := &fakeInspector{decision: Decision{Action: ActionAllow}}
	handler := newTestHandler(t, inspector, "first-token", &fakeSink{})

	post := func(token string) int {
		body, _ := json.Marshal(Request{
			ContractVersion: Version,
			Source:          SourceGeneric,
			Method:          http.MethodGet,
			Path:            "/",
			BodyState:       BodyStateAbsent,
		})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/adapter/inspect", bytes.NewReader(body))
		if token == "" {
			request.RemoteAddr = "127.0.0.1:54321"
		} else {
			request.RemoteAddr = "203.0.113.10:54321"
		}
		if token != "" {
			request.Header.Set("X-CheeseWAF-Adapter-Token", token)
		}
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	if code := post("first-token"); code != http.StatusOK {
		t.Fatalf("initial token status = %d", code)
	}
	handler.SetToken("second-token")
	if code := post("first-token"); code != http.StatusUnauthorized {
		t.Fatalf("retired token status = %d, want 401", code)
	}
	if code := post("second-token"); code != http.StatusOK {
		t.Fatalf("rotated token status = %d, want 200", code)
	}
	handler.SetToken("")
	if code := post(""); code != http.StatusOK {
		t.Fatalf("empty token from loopback status = %d, want 200", code)
	}
}

// A body at the contract maximum must survive base64 + JSON framing. The old
// limit rejected anything above roughly 24.75 MiB before validation ran.
func TestInspectAcceptsBodyAtContractLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a 32 MiB body")
	}
	inspector := &fakeInspector{decision: Decision{Action: ActionAllow}}
	handler := newTestHandler(t, inspector, "token", &fakeSink{})
	body := make([]byte, maxInspectBodyBytes)
	for i := range body {
		body[i] = 'a'
	}
	payload, err := json.Marshal(Request{
		ContractVersion: Version,
		Source:          SourceGeneric,
		Method:          http.MethodPost,
		Path:            "/upload",
		BodyState:       BodyStateForwarded,
		BodyForwarded:   true,
		Body:            body,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/adapter/inspect", bytes.NewReader(payload))
	request.RemoteAddr = "203.0.113.10:54321"
	request.Header.Set("X-CheeseWAF-Adapter-Token", "token")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("contract-limit body status = %d body=%s", recorder.Code, recorder.Body.String()[:min(200, recorder.Body.Len())])
	}
}
