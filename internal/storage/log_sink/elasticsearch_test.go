package log_sink

import (
	"testing"
	"time"

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

func TestElasticsearchTotal(t *testing.T) {
	if got := elasticsearchTotal(map[string]any{"value": float64(42)}, 0); got != 42 {
		t.Fatalf("unexpected total %d", got)
	}
	if got := elasticsearchTotal(nil, 7); got != 7 {
		t.Fatalf("unexpected fallback total %d", got)
	}
}
