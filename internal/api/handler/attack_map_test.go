package handler

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type attackMapSink struct {
	entries []storage.LogEntry
	filter  storage.LogFilter
}

func (s *attackMapSink) Write(context.Context, *storage.LogEntry) error { return nil }
func (s *attackMapSink) Flush(context.Context) error                    { return nil }
func (s *attackMapSink) Close() error                                   { return nil }
func (s *attackMapSink) Query(_ context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	s.filter = filter
	items := append([]storage.LogEntry(nil), s.entries...)
	if !filter.AfterTime.IsZero() || filter.AfterID != "" {
		filtered := items[:0]
		for _, item := range items {
			if item.Timestamp.After(filter.AfterTime) || (item.Timestamp.Equal(filter.AfterTime) && item.ID > filter.AfterID) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, int64(len(items)), nil
}

func TestAttackMapAggregateReturnsBoundedIncrementalProjection(t *testing.T) {
	when := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	sink := &attackMapSink{entries: []storage.LogEntry{
		{ID: "a", Timestamp: when, ClientIP: "203.0.113.8", Country: "CN", Action: "block", Category: "sqli", Severity: "high", StatusCode: 403, Payload: "must not appear", Metadata: map[string]any{"lat": 31.2, "lon": 121.5, "city": "Shanghai", "server_lat": 30.0, "server_lon": 120.0, "origin_lat": math.Inf(1), "secret": "must stay private", "region": map[string]any{"secret": "nested metadata must stay private"}}},
		{ID: "b", Timestamp: when.Add(time.Second), ClientIP: "203.0.113.9", Country: "CN", Action: "challenge", Category: "xss", Severity: "critical", StatusCode: 403, UserAgent: "private", Metadata: map[string]any{"lat": 31.2, "lon": 121.5, "city": "Shanghai"}},
	}}
	cfg := config.Default()
	h := New(Options{Config: &cfg, Sink: sink})
	recorder := httptest.NewRecorder()
	h.AttackMapAggregate(recorder, httptest.NewRequest(http.MethodGet, "/api/attack-map/aggregate?limit=10", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data attackMapAggregateResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Items) != 1 || envelope.Data.Items[0].Attacks != 2 || envelope.Data.Items[0].Blocked != 2 {
		t.Fatalf("unexpected aggregate: %+v", envelope.Data)
	}
	if envelope.Data.Items[0].Events[0].ID != "b" || envelope.Data.Next == nil || envelope.Data.Next.ID != "b" {
		t.Fatalf("unexpected cursor/events: %+v", envelope.Data)
	}
	body := recorder.Body.String()
	if containsMapLeak(body, "must not appear", "private", "must stay private", "nested metadata must stay private") {
		t.Fatalf("aggregate leaked evidence fields: %s", body)
	}
	if !strings.Contains(body, `"server_lat":30`) || !strings.Contains(body, `"server_lon":120`) {
		t.Fatalf("aggregate dropped protected-target projection: %s", body)
	}
	if sink.filter.Ascending || sink.filter.Kind != "security" || sink.filter.Limit != 10 {
		t.Fatalf("unexpected sink filter: %+v", sink.filter)
	}
}

func TestSourceIPPrefixHandlesCompressedIPv6(t *testing.T) {
	if got := sourceIPPrefix("2001:db8::1234"); got != "2001:db8::/64" {
		t.Fatalf("unexpected IPv6 prefix %q", got)
	}
	if got := sourceIPPrefix("::ffff:203.0.113.8"); got != "203.0.113.0/24" {
		t.Fatalf("unexpected mapped IPv4 prefix %q", got)
	}
}

func TestAttackMapAggregateUsesAscendingKeysetForUpdates(t *testing.T) {
	when := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	sink := &attackMapSink{entries: []storage.LogEntry{
		{ID: "a", Timestamp: when, Action: "block", Category: "sqli"},
		{ID: "b", Timestamp: when.Add(time.Second), Action: "block", Category: "xss"},
	}}
	cfg := config.Default()
	h := New(Options{Config: &cfg, Sink: sink})
	recorder := httptest.NewRecorder()
	target := "/api/attack-map/aggregate?after=" + when.Format(time.RFC3339Nano) + "&after_id=a"
	h.AttackMapAggregate(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !sink.filter.Ascending || !sink.filter.AfterTime.Equal(when) || sink.filter.AfterID != "a" {
		t.Fatalf("unexpected incremental filter: %+v", sink.filter)
	}
}

func TestAggregateAttackMapEntriesRetainsNewestRegionalEvents(t *testing.T) {
	base := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	entries := make([]storage.LogEntry, 0, 7)
	for index := 0; index < 7; index++ {
		entries = append(entries, storage.LogEntry{
			ID:        string(rune('a' + index)),
			Timestamp: base.Add(time.Duration(index) * time.Second),
			Country:   "CN",
			ClientIP:  "203.0.113.8",
			Action:    "block",
			Category:  "sqli",
		})
	}
	items := aggregateAttackMapEntries(entries)
	if len(items) != 1 || len(items[0].Events) != 6 {
		t.Fatalf("unexpected aggregate events: %+v", items)
	}
	if items[0].Events[0].ID != "g" || items[0].Events[5].ID != "b" {
		t.Fatalf("aggregate did not retain newest events: %+v", items[0].Events)
	}
}

func containsMapLeak(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
