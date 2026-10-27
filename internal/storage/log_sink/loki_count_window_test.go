package log_sink

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// A sub-second count window must stay sub-second: replacing it with the default
// day made totals include logs outside the selected range.
func TestLokiCountPreservesSubSecondWindow(t *testing.T) {
	recorder := newLokiRecorder(func(lokiRequest) (int, string) {
		return http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1758960000,"7"]}]}}`
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	sink := newLokiTestSink(t, server, config.LokiConfig{})
	end := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	total, supported, err := sink.Count(t.Context(), storage.LogFilter{
		StartTime: end.Add(-500 * time.Millisecond), EndTime: end,
	})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if !supported || total != 7 {
		t.Fatalf("supported=%v total=%d", supported, total)
	}
	requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("requests = %d", len(requests))
	}
	query := requests[0].query.Get("query")
	if !strings.Contains(query, "[500ms]") {
		t.Fatalf("logql %q does not preserve the requested window", query)
	}
	if strings.Contains(query, "86400") {
		t.Fatalf("logql %q fell back to the default day", query)
	}
}
