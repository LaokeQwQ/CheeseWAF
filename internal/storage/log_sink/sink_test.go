package log_sink

import (
	"context"
	"testing"

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
