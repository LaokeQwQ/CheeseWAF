package log_sink

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

func TestClickHouseQueryFetchesCountAndRows(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.URL.Query().Get("database"); got != "security" {
			t.Fatalf("unexpected database %q", got)
		}
		if user, pass, ok := r.BasicAuth(); !ok || user != "cw" || pass != "secret" {
			t.Fatalf("missing basic auth")
		}
		query := r.URL.Query().Get("query")
		switch {
		case strings.Contains(query, "count() AS total"):
			w.Write([]byte(`{"total":2}` + "\n"))
		case strings.Contains(query, "ORDER BY timestamp DESC LIMIT 25 OFFSET 5"):
			if !strings.Contains(query, "`cheesewaf_logs`") || !strings.Contains(query, "client_ip = '203.0.113.10'") {
				t.Fatalf("unexpected item query %q", query)
			}
			w.Write([]byte(`{"id":"1","timestamp":"2026-05-28T08:00:00Z","client_ip":"203.0.113.10","action":"block","category":"sqli","status_code":403,"latency":1000000,"tags":["scanner"],"metadata":{"score":9}}` + "\n"))
		default:
			t.Fatalf("unexpected query %q", query)
		}
	}))
	defer server.Close()

	sink, err := NewClickHouseSink(config.ClickHouseConfig{
		Endpoint: server.URL,
		Database: "security",
		Table:    "cheesewaf_logs",
		Username: "cw",
		Password: "secret",
	}, server.Client())
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	items, total, err := sink.Query(context.Background(), storage.LogFilter{
		ClientIP: "203.0.113.10",
		Limit:    25,
		Offset:   5,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
	if total != 2 || len(items) != 1 {
		t.Fatalf("unexpected result total=%d items=%+v", total, items)
	}
	if items[0].Timestamp != time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC) || items[0].Latency != time.Millisecond {
		t.Fatalf("unexpected decoded item %+v", items[0])
	}
}

func TestClickHouseRejectsUnsafeTableName(t *testing.T) {
	if _, err := NewClickHouseSink(config.ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Table: "logs;drop"}, nil); err == nil {
		t.Fatal("expected unsafe table to be rejected")
	}
}
