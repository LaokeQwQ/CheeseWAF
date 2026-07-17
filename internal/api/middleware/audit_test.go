package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
