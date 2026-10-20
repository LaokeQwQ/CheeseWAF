package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineResponseWriter struct {
	http.ResponseWriter
	deadlines []time.Time
	flushes   int
}

func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func (w *deadlineResponseWriter) Flush() {
	w.flushes++
}

func TestWithIdleWriteTimeoutRefreshesDeadline(t *testing.T) {
	const timeout = 50 * time.Millisecond
	base := &deadlineResponseWriter{ResponseWriter: httptest.NewRecorder()}
	handler := withIdleWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("second"))
	}), timeout)

	handler.ServeHTTP(base, httptest.NewRequest(http.MethodGet, "/", nil))
	if len(base.deadlines) != 5 {
		t.Fatalf("SetWriteDeadline called %d times, want 5", len(base.deadlines))
	}
	if base.flushes != 1 {
		t.Fatalf("Flush called %d times, want 1", base.flushes)
	}
	for i := 1; i < len(base.deadlines); i++ {
		if base.deadlines[i].Before(base.deadlines[i-1]) {
			t.Fatalf("deadline %d (%v) precedes deadline %d (%v)", i, base.deadlines[i], i-1, base.deadlines[i-1])
		}
	}
}

func TestWithIdleWriteTimeoutLeavesUnsupportedWriterUsable(t *testing.T) {
	base := httptest.NewRecorder()
	handler := withIdleWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Errorf("Write() error = %v", err)
		}
	}), time.Second)
	handler.ServeHTTP(base, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := base.Body.String(); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}
