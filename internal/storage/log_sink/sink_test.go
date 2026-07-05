package log_sink

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type queryOnlySink struct {
	items []storage.LogEntry
	total int64
	err   error
}

func (s queryOnlySink) Write(context.Context, *storage.LogEntry) error { return nil }
func (s queryOnlySink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return s.items, s.total, s.err
}
func (s queryOnlySink) Flush(context.Context) error { return nil }
func (s queryOnlySink) Close() error                { return nil }

func TestMultiSinkQueryFallsBackWhenFirstSinkIsEmpty(t *testing.T) {
	sink := &MultiSink{sinks: []storage.LogSink{
		queryOnlySink{items: []storage.LogEntry{}, total: 0},
		queryOnlySink{items: []storage.LogEntry{{ID: "external"}}, total: 1},
	}}
	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "external" {
		t.Fatalf("unexpected fallback result total=%d items=%+v", total, items)
	}
}

func TestNewFromConfigBlocksPrivateHTTPLogSinkByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	sink, err := NewFromConfig(config.StorageConfig{
		ClickHouse: config.ClickHouseConfig{
			Enabled:  true,
			Endpoint: server.URL,
			Database: "default",
			Table:    "cheesewaf_logs",
		},
	}, filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	err = sink.Write(context.Background(), &storage.LogEntry{ID: "private-sink-test"})
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("expected private log sink endpoint to be blocked, got %v", err)
	}
}

func TestNewFromConfigAllowsExplicitPrivateHTTPLogSink(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	sink, err := NewFromConfig(config.StorageConfig{
		VictoriaLogs: config.VictoriaLogsConfig{
			Enabled:              true,
			Endpoint:             server.URL,
			AllowPrivateEndpoint: true,
		},
	}, filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "private-sink-allowed"}); err != nil {
		t.Fatalf("expected explicit private log sink endpoint to write: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected one remote write request, got %d", requests)
	}
}
