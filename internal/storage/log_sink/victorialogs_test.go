package log_sink

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestVictoriaLogsQueryUsesLogsQLAndDecodesRows(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/select/logsql/query" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		query := r.Form.Get("query")
		if !strings.Contains(query, `client_ip:="198.51.100.9"`) || !strings.Contains(query, `tags:="bot"`) {
			t.Fatalf("unexpected query %q", query)
		}
		switch {
		case strings.Contains(query, "stats count() total"):
			w.Write([]byte(`{"total":"3"}` + "\n"))
		default:
			if r.Form.Get("limit") != "10" || r.Form.Get("offset") != "2" {
				t.Fatalf("unexpected pagination limit=%q offset=%q", r.Form.Get("limit"), r.Form.Get("offset"))
			}
			w.Write([]byte(`{"_time":"2026-05-28T08:00:01Z","id":"vl-1","client_ip":"198.51.100.9","action":"challenge","category":"bot","status_code":"403","latency":"2000000","tags":["bot"]}` + "\n"))
		}
	}))
	defer server.Close()

	sink, err := NewVictoriaLogsSink(config.VictoriaLogsConfig{Endpoint: server.URL + "/insert/jsonline"}, server.Client())
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	items, total, err := sink.Query(context.Background(), storage.LogFilter{
		ClientIP: "198.51.100.9",
		Tags:     []string{"bot"},
		Limit:    10,
		Offset:   2,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
	if total != 3 || len(items) != 1 {
		t.Fatalf("unexpected result total=%d items=%+v", total, items)
	}
	if items[0].Timestamp != time.Date(2026, 5, 28, 8, 0, 1, 0, time.UTC) || items[0].Latency != 2*time.Millisecond {
		t.Fatalf("unexpected decoded item %+v", items[0])
	}
}

func TestVictoriaLogsWriteAddsEventTime(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sink, err := NewVictoriaLogsSink(config.VictoriaLogsConfig{Endpoint: server.URL + "/insert/jsonline"}, server.Client())
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	when := time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC)
	if err := sink.Write(context.Background(), &storage.LogEntry{ID: "1", Timestamp: when, Message: "blocked sql injection"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(body, `"_time":"2026-05-28T08:00:00Z"`) || !strings.Contains(body, `"_msg":"blocked sql injection"`) {
		t.Fatalf("victorialogs payload missing indexed fields: %s", body)
	}
}
