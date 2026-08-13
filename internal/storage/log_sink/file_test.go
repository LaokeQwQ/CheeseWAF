package log_sink

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestFileSinkQueryClampsLargeLimit(t *testing.T) {
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	base := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	for i := 0; i < maxFileSinkQueryLimit+5; i++ {
		if err := sink.Write(context.Background(), &storage.LogEntry{ID: fmt.Sprintf("entry-%04d", i), Timestamp: base.Add(time.Duration(i) * time.Second), Action: "block"}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: maxFileSinkQueryLimit * 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != int64(maxFileSinkQueryLimit+5) || len(items) != maxFileSinkQueryLimit {
		t.Fatalf("expected total preserved and page clamped, total=%d len=%d", total, len(items))
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

func TestFileSinkFullScanKeepsOnlyRequestedWindow(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "0")
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()

	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10_000; i++ {
		if err := sink.Write(context.Background(), &storage.LogEntry{
			ID:        fmt.Sprintf("entry-%05d", i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Action:    "block",
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	items, total, err := sink.Query(context.Background(), storage.LogFilter{Offset: 2, Limit: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 10_000 || len(items) != 1 || items[0].ID != "entry-09997" {
		t.Fatalf("unexpected bounded page: total=%d items=%+v", total, items)
	}
}

func TestLogQueryHeapPreservesStableTimestampOrder(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	h := logQueryHeap{}
	for i := 0; i < 5; i++ {
		candidate := retainedLogEntry{
			entry:    storage.LogEntry{ID: fmt.Sprintf("entry-%d", i), Timestamp: base},
			sequence: int64(i),
		}
		if len(h) < 2 {
			heap.Push(&h, candidate)
		} else if newerLogEntry(candidate, h[0]) {
			heap.Pop(&h)
			heap.Push(&h, candidate)
		}
	}
	if len(h) != 2 {
		t.Fatalf("heap retained %d rows, want 2", len(h))
	}
	kept := map[string]bool{h[0].entry.ID: true, h[1].entry.ID: true}
	if !kept["entry-0"] || !kept["entry-1"] {
		t.Fatalf("stable window retained wrong rows: %+v", h)
	}
}

func TestFileSinkRotatesBeforeWriteAndQueriesRetainedSegmentsAfterRestart(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "0")
	path := filepath.Join(t.TempDir(), "access.log")
	sink, err := NewFileSinkWithRotation(path, 1024, 2)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	for i := 0; i < 5; i++ {
		entry := &storage.LogEntry{
			ID:        fmt.Sprintf("rotation-%d", i),
			Timestamp: time.Date(2026, 8, 10, 12, 0, i, 0, time.UTC),
			Action:    "block",
			URI:       strings.Repeat("u", 600),
			Message:   strings.Repeat("m", 600),
			Payload:   strings.Repeat("x", 600),
			UserAgent: strings.Repeat("a", 600),
		}
		if err := sink.Write(context.Background(), entry); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if err := sink.Flush(context.Background()); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
		for _, segment := range []string{path, path + ".1", path + ".2"} {
			if info, statErr := os.Stat(segment); statErr == nil && info.Size() > 1024 {
				t.Fatalf("segment %s exceeded configured size: %d", segment, info.Size())
			}
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("unexpected stale third backup, err=%v", err)
	}
	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query retained segments: %v", err)
	}
	if total != 3 || fmt.Sprint(ids(items)) != "[rotation-4 rotation-3 rotation-2]" {
		t.Fatalf("retained query total=%d items=%v", total, ids(items))
	}
	count, _, err := sink.Count(context.Background(), storage.LogFilter{Category: "missing"})
	if err != nil || count != 0 {
		t.Fatalf("count across segments = %d, err=%v", count, err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := NewFileSinkWithRotation(path, 1024, 2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	items, total, err = reopened.Query(context.Background(), storage.LogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query after restart: %v", err)
	}
	if total != 3 || fmt.Sprint(ids(items)) != "[rotation-4 rotation-3 rotation-2]" {
		t.Fatalf("after restart total=%d items=%v", total, ids(items))
	}
}

func TestFileSinkDropsOldSegmentsWhenBackupsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	sink, err := NewFileSinkWithRotation(path, 1024, 0)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	for i := 0; i < 3; i++ {
		if err := sink.Write(context.Background(), &storage.LogEntry{ID: fmt.Sprintf("only-%d", i), Action: "pass", Payload: strings.Repeat("y", 600)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "only-2" {
		t.Fatalf("backup-disabled query total=%d items=%v", total, ids(items))
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("backup created while disabled, err=%v", err)
	}
}

func TestFileSinkBoundsOversizedLogLineAndPreservesUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	entry := &storage.LogEntry{
		ID:      "oversized",
		Action:  "block",
		Message: strings.Repeat("消息", 2<<20),
		Payload: strings.Repeat("payload", 2<<20),
		Metadata: map[string]any{
			"nested": strings.Repeat("元数据", 2<<20),
		},
	}
	if err := sink.Write(context.Background(), entry); err != nil {
		t.Fatalf("write oversized entry: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxFileSinkScanLineBytes)
	if !scanner.Scan() {
		t.Fatalf("expected one bounded log line, err=%v", scanner.Err())
	}
	line := append([]byte(nil), scanner.Bytes()...)
	if len(line) > maxFileSinkWriteLineBytes || len(line) > maxFileSinkScanLineBytes {
		t.Fatalf("bounded line length=%d", len(line))
	}
	if !utf8.Valid(line) {
		t.Fatal("bounded log line is not valid UTF-8")
	}
	var decoded storage.LogEntry
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("decode bounded line: %v", err)
	}
	if decoded.ID != "oversized" || utf8.RuneCountInString(decoded.Payload) >= utf8.RuneCountInString(entry.Payload) {
		t.Fatalf("oversized payload was not bounded: id=%q payload_runes=%d", decoded.ID, utf8.RuneCountInString(decoded.Payload))
	}
}

func TestFileSinkSkipsOversizedHistoricalLineAndContinues(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "0")
	path := filepath.Join(t.TempDir(), "access.log")
	first, err := json.Marshal(storage.LogEntry{ID: "first", Timestamp: time.Unix(1, 0).UTC(), Action: "pass"})
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	last, err := json.Marshal(storage.LogEntry{ID: "last", Timestamp: time.Unix(2, 0).UTC(), Action: "block"})
	if err != nil {
		t.Fatalf("marshal last: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	if _, err := file.Write(append(first, '\n')); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := file.WriteString(strings.Repeat("x", maxFileSinkScanLineBytes+1) + "\n"); err != nil {
		t.Fatalf("write oversized line: %v", err)
	}
	if _, err := file.Write(append(last, '\n')); err != nil {
		t.Fatalf("write last: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close seed log: %v", err)
	}

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	defer sink.Close()
	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 2 || fmt.Sprint(ids(items)) != "[last first]" {
		t.Fatalf("oversized historical line affected query: total=%d items=%v", total, ids(items))
	}
}

func TestFileSinkRejectsUnboundedQueryOffset(t *testing.T) {
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	maxInt := int(^uint(0) >> 1)
	_, _, err = sink.Query(context.Background(), storage.LogFilter{Offset: maxInt, Limit: 1})
	if err == nil || !strings.Contains(err.Error(), "maximum window") {
		t.Fatalf("huge offset error = %v", err)
	}
}

func TestFileSinkRecentCacheHonorsByteBudget(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "100")
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_BYTES", "900")
	path := filepath.Join(t.TempDir(), "access.log")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	for index := 0; index < 6; index++ {
		entry := &storage.LogEntry{
			ID:        fmt.Sprintf("entry-%d", index),
			Timestamp: time.Unix(int64(index+1), 0).UTC(),
			Action:    "pass",
			Payload:   strings.Repeat(string(rune('a'+index)), 300),
		}
		if err := sink.Write(context.Background(), entry); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
		if sink.recentBytes > sink.recentMaxBytes {
			t.Fatalf("cache exceeded byte budget: bytes=%d max=%d", sink.recentBytes, sink.recentMaxBytes)
		}
	}
	if sink.recentCount >= 6 || sink.recentCount == 0 {
		t.Fatalf("byte budget did not evict a bounded suffix: count=%d", sink.recentCount)
	}
	recent := sink.recentSnapshotLocked()
	if got := recent[len(recent)-1].ID; got != "entry-5" {
		t.Fatalf("cache is not a contiguous newest suffix: last=%q", got)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if reopened.recentBytes > reopened.recentMaxBytes || reopened.recentCount != sink.recentCount {
		t.Fatalf("rebuilt cache violates budget: bytes=%d max=%d count=%d want_count=%d", reopened.recentBytes, reopened.recentMaxBytes, reopened.recentCount, sink.recentCount)
	}
	items, total, err := reopened.Query(context.Background(), storage.LogFilter{Limit: 6})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 6 || fmt.Sprint(ids(items)) != "[entry-5 entry-4 entry-3 entry-2 entry-1 entry-0]" {
		t.Fatalf("bounded cache changed query results: total=%d items=%v", total, ids(items))
	}
}

func TestFileSinkOversizedCacheEntryInvalidatesRecentSuffix(t *testing.T) {
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_LIMIT", "10")
	t.Setenv("CHEESEWAF_FILE_SINK_CACHE_BYTES", "128")
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "access.log"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "large", Action: "block", Payload: strings.Repeat("x", 512)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if sink.recentCount != 0 || sink.recentBytes != 0 {
		t.Fatalf("oversized cache entry left an incomplete suffix: count=%d bytes=%d", sink.recentCount, sink.recentBytes)
	}
	items, total, err := sink.Query(context.Background(), storage.LogFilter{Limit: 1})
	if err != nil {
		t.Fatalf("query fallback: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "large" {
		t.Fatalf("disk fallback lost oversized cache entry: total=%d items=%v", total, ids(items))
	}
}

func TestFileSinkRotationFailureReopensActiveFileAndRebuildsIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	sink, err := NewFileSinkWithRotation(path, 512, 1)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	if err := sink.Write(context.Background(), &storage.LogEntry{
		ID:        "existing",
		Timestamp: time.Unix(1, 0).UTC(),
		Action:    "pass",
		Payload:   strings.Repeat("x", 600),
	}); err != nil {
		t.Fatalf("write existing: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("flush existing: %v", err)
	}
	if err := os.Mkdir(path+".1", 0o750); err != nil {
		t.Fatalf("create blocking backup directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path+".1", "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("make blocking backup directory non-empty: %v", err)
	}

	err = sink.Write(context.Background(), &storage.LogEntry{
		ID:        "rejected",
		Timestamp: time.Unix(2, 0).UTC(),
		Action:    "block",
		Payload:   strings.Repeat("y", 600),
	})
	if err == nil {
		t.Fatal("expected rotation failure")
	}
	items, total, queryErr := sink.Query(context.Background(), storage.LogFilter{Limit: 10})
	if queryErr != nil {
		t.Fatalf("query after rotation failure: %v", queryErr)
	}
	if total != 1 || fmt.Sprint(ids(items)) != "[existing]" {
		t.Fatalf("index diverged after rotation failure: total=%d items=%v", total, ids(items))
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close after rotation failure: %v", err)
	}
}

func TestFileSinkBoundsHostileMetadataWithoutPanic(t *testing.T) {
	type privateFields struct {
		Exported string `json:"exported"`
		hidden   string
	}
	type node struct {
		Next *node `json:"next"`
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	linked := &node{}
	linked.Next = linked
	var typedNil *node
	entry := storage.LogEntry{
		ID:     "hostile-metadata",
		Action: "block",
		Metadata: map[string]any{
			"cycle":        cycle,
			"linked":       linked,
			"typed_nil":    typedNil,
			"deep":         []any{map[string]any{"a": []any{map[string]any{"b": []any{"value"}}}}},
			"struct":       privateFields{Exported: strings.Repeat("e", 1<<20), hidden: "secret"},
			"invalid_utf8": string([]byte{'a', 0xff, 'b'}),
			"nan":          math.NaN(),
			"infinity":     math.Inf(1),
		},
	}
	data, stored, err := marshalBoundedLogEntry(entry, 16<<10)
	if err != nil {
		t.Fatalf("marshal hostile metadata: %v", err)
	}
	if len(data) > 16<<10 {
		t.Fatalf("hostile metadata output is unbounded: %d", len(data))
	}
	if !utf8.Valid(data) {
		t.Fatal("hostile metadata output is not valid UTF-8")
	}
	if stored.ID != entry.ID {
		t.Fatalf("stored entry lost identity: %+v", stored)
	}
}

func ids(items []storage.LogEntry) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}
