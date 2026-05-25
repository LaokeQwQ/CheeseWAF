package log_sink

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestFileSinkQueryFiltersEntries(t *testing.T) {
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	now := time.Now().UTC()
	_ = sink.Write(context.Background(), &storage.LogEntry{ID: "1", Timestamp: now, ClientIP: "203.0.113.10", Action: "block", Category: "sqli"})
	_ = sink.Write(context.Background(), &storage.LogEntry{ID: "2", Timestamp: now, ClientIP: "198.51.100.2", Action: "pass", Category: ""})

	items, total, err := sink.Query(context.Background(), storage.LogFilter{Action: "block", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "1" {
		t.Fatalf("unexpected query result: total=%d items=%+v", total, items)
	}
}
