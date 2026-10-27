package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	auditpkg "github.com/LaokeQwQ/CheeseWAF/internal/audit"
)

type capturedAuditEvents struct {
	mu     sync.Mutex
	events []auditpkg.Event
}

func (c *capturedAuditEvents) append(_ context.Context, event auditpkg.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	return nil
}

func (c *capturedAuditEvents) snapshot() []auditpkg.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]auditpkg.Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestAuditorEmitsSignedEventsForManagementRequests(t *testing.T) {
	captured := &capturedAuditEvents{}
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	auditor.SetEventSink("control", "tenant-a", 7, captured.append)

	handler := auditor.MiddlewareWithSource(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), nil)

	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/users/u-1"},
		{http.MethodGet, "/api/users/u-1"},
		{http.MethodPost, "/api/sites/s-1"},
	} {
		req := httptest.NewRequest(route.method, route.path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status=%d for %s %s", recorder.Code, route.method, route.path)
		}
	}

	events := captured.snapshot()
	if len(events) != 3 {
		t.Fatalf("events=%d, want 3", len(events))
	}
	cases := []struct {
		class     auditpkg.EventClass
		eventType auditpkg.EventType
	}{
		{auditpkg.EventClassCritical, auditpkg.EventTypeConfigChanged},
		{auditpkg.EventClassNormal, auditpkg.EventTypeAudit},
		{auditpkg.EventClassNormal, auditpkg.EventTypeConfigChanged},
	}
	for i, want := range cases {
		if events[i].Class != want.class || events[i].Type != want.eventType {
			t.Fatalf("event %d class=%s type=%s, want %s/%s", i, events[i].Class, events[i].Type, want.class, want.eventType)
		}
		if events[i].Actor != "anonymous" || events[i].PolicyEpoch != 7 || events[i].StreamID != "control" || events[i].TenantID != "tenant-a" {
			t.Fatalf("event %d = %+v", i, events[i])
		}
		if events[i].At.IsZero() || events[i].EventID == "" || events[i].Resource == "" {
			t.Fatalf("event %d is missing required fields: %+v", i, events[i])
		}
		if _, err := time.Parse(time.RFC3339, events[i].At.UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("event time: %v", err)
		}
	}
}

func TestAuditorSignedSinkFailureKeepsResponse(t *testing.T) {
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	auditor.SetEventSink("control", "tenant-a", 1, func(context.Context, auditpkg.Event) error {
		return context.DeadlineExceeded
	})
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/system/config", nil))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201", recorder.Code)
	}
}
