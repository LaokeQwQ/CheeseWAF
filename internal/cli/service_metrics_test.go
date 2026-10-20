package cli

import (
	"context"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type exactMonitorCountSink struct {
	counts  map[string]int64
	queries int
}

func (s *exactMonitorCountSink) Write(context.Context, *storage.LogEntry) error { return nil }
func (s *exactMonitorCountSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.queries++
	return nil, 0, nil
}
func (s *exactMonitorCountSink) Flush(context.Context) error { return nil }
func (s *exactMonitorCountSink) Close() error                { return nil }
func (s *exactMonitorCountSink) Count(_ context.Context, filter storage.LogFilter) (int64, bool, error) {
	key := filter.Action
	return s.counts[key], true, nil
}

func TestExactMonitorLogTotalsUsesUnboundedSinkCounts(t *testing.T) {
	sink := &exactMonitorCountSink{counts: map[string]int64{"": 2501, "block": 1200, "challenge": 801}}
	requests, blocked, challenges, ok := exactMonitorLogTotals(context.Background(), sink)
	if !ok {
		t.Fatal("expected exact counts to be available")
	}
	if requests != 2501 || blocked != 1200 || challenges != 801 {
		t.Fatalf("exact counts = %d/%d/%d, want 2501/1200/801", requests, blocked, challenges)
	}
	if sink.queries != 0 {
		t.Fatalf("exact-count path queried bounded log samples %d time(s)", sink.queries)
	}
}

func TestExactMonitorLogTotalsFallsBackWhenCountUnsupported(t *testing.T) {
	var sink storage.LogSink = &queryOnlyMonitorSink{}
	if _, _, _, ok := exactMonitorLogTotals(context.Background(), sink); ok {
		t.Fatal("unsupported count sink must select bounded query fallback")
	}
}

type queryOnlyMonitorSink struct{}

func (*queryOnlyMonitorSink) Write(context.Context, *storage.LogEntry) error { return nil }
func (*queryOnlyMonitorSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}
func (*queryOnlyMonitorSink) Flush(context.Context) error { return nil }
func (*queryOnlyMonitorSink) Close() error                { return nil }
