package edge

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type failingResponseWriter struct {
	header http.Header
	err    error
}

func (w *failingResponseWriter) Header() http.Header       { return w.header }
func (w *failingResponseWriter) WriteHeader(int)           {}
func (w *failingResponseWriter) Write([]byte) (int, error) { return 0, w.err }

func TestAdaptiveCaptureWriterSpillsBufferedResponseOnce(t *testing.T) {
	destination := httptest.NewRecorder()
	destination.Header().Set("Content-Security-Policy", "default-src 'none'")
	writer := NewAdaptiveCaptureWriter(destination, 5)
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusCreated)
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if destination.Body.Len() != 0 {
		t.Fatal("response must remain buffered while it fits")
	}
	if _, err := writer.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("ghi")); err != nil {
		t.Fatal(err)
	}
	if !writer.TooLarge() || !writer.Committed() {
		t.Fatal("writer must switch to streaming after exceeding the limit")
	}
	if destination.Code != http.StatusCreated || destination.Body.String() != "abcdefghi" {
		t.Fatalf("unexpected streamed response: code=%d body=%q", destination.Code, destination.Body.String())
	}
	if got := destination.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("response headers were not preserved: %q", got)
	}
	if got := destination.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Fatalf("outer middleware header was removed: %q", got)
	}
}

func TestAdaptiveCaptureWriterRetainsCommittedWriteError(t *testing.T) {
	want := errors.New("downstream disconnected")
	destination := &failingResponseWriter{header: make(http.Header), err: want}
	writer := NewAdaptiveCaptureWriter(destination, 2)
	if _, err := writer.Write([]byte("abc")); !errors.Is(err, want) {
		t.Fatalf("expected downstream write error, got %v", err)
	}
	if !writer.Committed() || !errors.Is(writer.Err(), want) {
		t.Fatalf("committed write error was not retained: committed=%v err=%v", writer.Committed(), writer.Err())
	}
}
