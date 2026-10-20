package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestMonitorSnapshotUsesQueryTotalsNotSampleLimit(t *testing.T) {
	sink := &countingLogSink{
		items: []storage.LogEntry{
			{ID: "1", Timestamp: time.Now().UTC(), Action: "pass", StatusCode: http.StatusOK},
			{ID: "2", Timestamp: time.Now().UTC(), Action: "block", Category: "sqli", StatusCode: http.StatusForbidden},
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
	if snapshot.StatusCodes[http.StatusOK] != 1 || snapshot.StatusCodes[http.StatusForbidden] != 1 {
		t.Fatalf("expected sampled status counts, got %+v", snapshot.StatusCodes)
	}
	if snapshot.Categories["sqli"] != 1 {
		t.Fatalf("expected sampled category count, got %+v", snapshot.Categories)
	}
}

func TestMetricsUsesExactTotalsAndBoundedSampleDimensions(t *testing.T) {
	sink := &countingLogSink{
		items: []storage.LogEntry{
			{ID: "sample", Timestamp: time.Now().UTC(), Action: "block", Category: "xss", StatusCode: http.StatusForbidden},
			{ID: "untrusted", Timestamp: time.Now().UTC(), Action: "pass", Category: "tenant-90210", StatusCode: 9001},
		},
		totals: map[string]int64{"": 2501, "block": 1200, "challenge": 801},
	}
	h := &Handler{Config: &config.Config{}, Sink: sink, StartedAt: time.Now().Add(-time.Minute)}
	rec := httptest.NewRecorder()
	h.Metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"cheesewaf_requests_total 2501",
		"cheesewaf_blocked_total 1200",
		"cheesewaf_challenges_total 801",
		`cheesewaf_status_total{code="403"} 1`,
		`cheesewaf_attack_category_total{category="xss"} 1`,
		`cheesewaf_attack_category_total{category="other"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "tenant-90210") || strings.Contains(body, `code="9001"`) {
		t.Fatalf("metrics exposed an unbounded category or invalid status code:\n%s", body)
	}
	if len(sink.queries) != 1 || sink.queries[0].Limit != 1000 {
		t.Fatalf("metrics must use one bounded sample query, got %+v", sink.queries)
	}
}

type countingLogSink struct {
	items   []storage.LogEntry
	totals  map[string]int64
	queries []storage.LogFilter
}

func (s *countingLogSink) Write(context.Context, *storage.LogEntry) error {
	return nil
}

func (s *countingLogSink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.queries = append(s.queries, filter)
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

func (s *countingLogSink) Count(_ context.Context, filter storage.LogFilter) (int64, bool, error) {
	if total, ok := s.totals[filter.Action]; ok {
		return total, true, nil
	}
	return 0, true, nil
}

func (s *countingLogSink) Flush(context.Context) error {
	return nil
}

func (s *countingLogSink) Close() error {
	return nil
}
