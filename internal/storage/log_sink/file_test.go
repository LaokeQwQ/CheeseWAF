package log_sink

import (
	"context"
	"fmt"
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

func TestFileSinkQueryReturnsNewestFirst(t *testing.T) {
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	base := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	_ = sink.Write(context.Background(), &storage.LogEntry{ID: "old", Timestamp: base, Action: "block", Category: "sqli"})
	_ = sink.Write(context.Background(), &storage.LogEntry{ID: "new", Timestamp: base.Add(time.Minute), Action: "block", Category: "xss"})

	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 2})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("unexpected counts: total=%d len=%d", total, len(items))
	}
	if items[0].ID != "new" || items[1].ID != "old" {
		t.Fatalf("expected newest first, got %+v", items)
	}
}

func TestFileSinkRecentCacheReturnsTotalWithoutFullPageLoss(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "3")
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		action := "pass"
		if i%2 == 0 {
			action = "block"
		}
		if err := sink.Write(context.Background(), &storage.LogEntry{
			ID:        fmt.Sprintf("entry-%02d", i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Action:    action,
			Category:  "sqli",
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 8 {
		t.Fatalf("expected full total 8 from index, got %d", total)
	}
	if got := ids(items); fmt.Sprint(got) != "[entry-07 entry-06 entry-05]" {
		t.Fatalf("expected newest cached page, got %v", got)
	}

	blocked, ok, err := sink.Count(context.Background(), storage.LogFilter{Action: "block"})
	if err != nil || !ok {
		t.Fatalf("count err=%v ok=%v", err, ok)
	}
	if blocked != 4 {
		t.Fatalf("expected full block count 4, got %d", blocked)
	}
}

func TestFileSinkRecentCacheFallsBackWhenTimeRangeExceedsCache(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "2")
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := sink.Write(context.Background(), &storage.LogEntry{
			ID:        fmt.Sprintf("entry-%02d", i),
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Action:    "block",
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	items, total, err := sink.Query(context.Background(), storage.LogFilter{
		StartTime: base,
		EndTime:   base.Add(90 * time.Second),
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected two full-scan matches, got total=%d items=%+v", total, items)
	}
	if got := ids(items); fmt.Sprint(got) != "[entry-01 entry-00]" {
		t.Fatalf("expected fallback full-scan items, got %v", got)
	}
}

func ids(items []storage.LogEntry) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}
