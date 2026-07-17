package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type auditFakeClock struct {
	now time.Time
}

func (c *auditFakeClock) Now() time.Time {
	return c.now
}

type deadlineResponseWriter struct {
	header   http.Header
	deadline time.Time
	called   bool
}

func (w *deadlineResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (w *deadlineResponseWriter) WriteHeader(int) {}

func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	w.called = true
	return nil
}

func TestStatusRecorderUnwrapAllowsResponseControllerWriteDeadline(t *testing.T) {
	base := &deadlineResponseWriter{}
	recorder := &statusRecorder{ResponseWriter: base, status: http.StatusOK}

	if err := http.NewResponseController(recorder).SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("set write deadline through statusRecorder: %v", err)
	}
	if !base.called {
		t.Fatal("expected underlying response writer SetWriteDeadline to be called")
	}
	if !base.deadline.IsZero() {
		t.Fatalf("expected zero write deadline, got %s", base.deadline)
	}
}

func TestStatusRecorderAllowsStreamingPastServerWriteTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		recorder.Header().Set("Content-Type", "text/event-stream")
		if err := http.NewResponseController(recorder).SetWriteDeadline(time.Time{}); err != nil {
			t.Errorf("set write deadline through statusRecorder: %v", err)
			return
		}
		_, _ = recorder.Write([]byte("event: trace\ndata: {}\n\n"))
		recorder.Flush()
		time.Sleep(250 * time.Millisecond)
		_, _ = recorder.Write([]byte("event: done\ndata: {}\n\n"))
		recorder.Flush()
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.WriteTimeout = 80 * time.Millisecond
	server.Start()
	defer server.Close()

	client := server.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("get streaming response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read streaming response: %v", err)
	}
	if got := string(body); !strings.Contains(got, "event: done") {
		t.Fatalf("stream ended before delayed event, body:\n%s", got)
	}
}

func TestAuditorWithClockUsesControlledUTCTimestamp(t *testing.T) {
	now := time.Date(2024, time.November, 5, 13, 14, 15, 0, time.FixedZone("test", 7*60*60))
	clock := &auditFakeClock{now: now}
	auditor := NewAuditorWithClock(filepath.Join(t.TempDir(), "audit.jsonl"), clock)
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/test", nil))

	entries, err := auditor.Query(1)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	if !entries[0].Timestamp.Equal(now.UTC()) || entries[0].Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp = %s (%s), want %s (UTC)", entries[0].Timestamp, entries[0].Timestamp.Location(), now.UTC())
	}
}

func TestAuditorClockOffsetDoesNotAffectLatency(t *testing.T) {
	startWall := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	clock := &auditFakeClock{now: startWall}
	auditor := NewAuditorWithClock(filepath.Join(t.TempDir(), "audit.jsonl"), clock)
	handler := auditor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		clock.now = clock.now.Add(50 * 365 * 24 * time.Hour)
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/test", nil))

	entries, err := auditor.Query(1)
	if err != nil {
		t.Fatalf("query audit entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	if entries[0].LatencyMS < 15 || entries[0].LatencyMS > 5_000 {
		t.Fatalf("latency = %dms, want monotonic request duration independent of wall-clock offset", entries[0].LatencyMS)
	}
	wantTimestamp := startWall.Add(50 * 365 * 24 * time.Hour)
	if !entries[0].Timestamp.Equal(wantTimestamp) {
		t.Fatalf("timestamp = %s, want shifted wall time %s", entries[0].Timestamp, wantTimestamp)
	}
}
