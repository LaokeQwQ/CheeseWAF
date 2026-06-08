package handler

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestMonitorSnapshotUsesQueryTotalsNotSampleLimit(t *testing.T) {
	sink := &countingLogSink{
		items: []storage.LogEntry{
			{ID: "1", Timestamp: time.Now().UTC(), Action: "pass"},
			{ID: "2", Timestamp: time.Now().UTC(), Action: "block", Category: "sqli"},
		},
		totals: map[string]int64{
			"":          1500,
			"block":     320,
			"challenge": 42,
		},
	}
	handler := &Handler{
		Config:    &config.Config{},
		Sink:      sink,
		StartedAt: time.Now().Add(-time.Minute),
	}
	snapshot := handler.monitorSnapshot(httptest.NewRequest("GET", "/monitor", nil))

	if snapshot.Requests != 1500 {
		t.Fatalf("expected request total 1500, got %d", snapshot.Requests)
	}
	if snapshot.Blocked != 320 {
		t.Fatalf("expected blocked total 320, got %d", snapshot.Blocked)
	}
	if snapshot.Challenges != 42 {
		t.Fatalf("expected challenge total 42, got %d", snapshot.Challenges)
	}
}

type countingLogSink struct {
	items  []storage.LogEntry
	totals map[string]int64
}

func (s *countingLogSink) Write(context.Context, *storage.LogEntry) error {
	return nil
}

func (s *countingLogSink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	total, ok := s.totals[filter.Action]
	if !ok {
		total = int64(len(s.items))
	}
	if filter.Action == "" {
		return s.items, total, nil
	}
	filtered := make([]storage.LogEntry, 0, len(s.items))
	for _, item := range s.items {
		if item.Action == filter.Action {
			filtered = append(filtered, item)
		}
	}
	return filtered, total, nil
}

func (s *countingLogSink) Flush(context.Context) error {
	return nil
}

func (s *countingLogSink) Close() error {
	return nil
}
