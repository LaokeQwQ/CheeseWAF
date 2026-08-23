package log_sink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestElasticsearchQueryBuildsFilters(t *testing.T) {
	query := elasticsearchQuery(storage.LogFilter{
		SiteID:    "site-a",
		ClientIP:  "192.0.2.10",
		Action:    "block",
		Tags:      []string{"scanner"},
		StartTime: time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC),
		Limit:     25,
	})
	if query["size"] != 25 {
		t.Fatalf("unexpected size: %+v", query["size"])
	}
	boolQuery, ok := query["query"].(map[string]any)["bool"].(map[string]any)
	if !ok {
		t.Fatalf("expected bool query: %+v", query)
	}
	filters, ok := boolQuery["filter"].([]map[string]any)
	if !ok || len(filters) < 5 {
		t.Fatalf("expected filters, got %+v", boolQuery["filter"])
	}
}

func TestElasticsearchQueryUsesLiteralSearchAndNonEmptySecurityCategory(t *testing.T) {
	query := elasticsearchQuery(storage.LogFilter{
		Search:    `trace:(foo OR *)`,
		Kind:      "security",
		AfterTime: time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC),
		AfterID:   "event-10",
		Ascending: true,
		Limit:     25,
	})
	raw, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"multi_match"`, `"phrase_prefix"`, `trace:(foo OR *)`, `"wildcard"`, `"?*"`, `detector_id.keyword`, `severity.keyword`, `monitor`, `"gt"`, `"order":"asc"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("query missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, `"query_string"`) || strings.Contains(text, `"exists"`) {
		t.Fatalf("query interprets search syntax or treats empty categories as security: %s", text)
	}
}

func TestElasticsearchTotal(t *testing.T) {
	if got := elasticsearchTotal(map[string]any{"value": float64(42)}, 0); got != 42 {
		t.Fatalf("unexpected total %d", got)
	}
	if got := elasticsearchTotal(nil, 7); got != 7 {
		t.Fatalf("unexpected fallback total %d", got)
	}
}

func TestElasticsearchQueryRejectsRowsBeyondLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":2},"hits":[{"_source":{"id":"1"}},{"_source":{"id":"2"}}]}}`))
	}))
	defer server.Close()

	sink, err := NewElasticsearchSink(config.ElasticsearchConfig{Enabled: true, Endpoint: server.URL}, server.Client())
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	if _, _, err := sink.Query(context.Background(), storage.LogFilter{Limit: 1}); err == nil || !strings.Contains(err.Error(), "exceeds 1 rows") {
		t.Fatalf("expected bounded row error, got %v", err)
	}
}

func TestElasticsearchQueryRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"padding":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxLogQueryResponseBytes))))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer server.Close()

	sink, err := NewElasticsearchSink(config.ElasticsearchConfig{Enabled: true, Endpoint: server.URL}, server.Client())
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	if _, _, err := sink.Query(context.Background(), storage.LogFilter{Limit: 1}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded response error, got %v", err)
	}
}
