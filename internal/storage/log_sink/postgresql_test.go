package log_sink

import (
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestQuoteIdentifierPath(t *testing.T) {
	got, err := quoteIdentifierPath("public.cheesewaf_logs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `"public"."cheesewaf_logs"` {
		t.Fatalf("unexpected quoted identifier %q", got)
	}

	for _, value := range []string{"bad-name", "public.logs;drop", "a.b.c", "1logs"} {
		if _, err := quoteIdentifierPath(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestPostgreSQLWhere(t *testing.T) {
	start := time.Date(2026, 5, 28, 8, 0, 0, 0, time.UTC)
	where, args, err := postgresqlWhere(storage.LogFilter{
		SiteID:    "default",
		ClientIP:  "192.0.2.10",
		Category:  "sqli",
		Action:    "block",
		TraceID:   "cw-1",
		Tags:      []string{"scanner"},
		StartTime: start,
		EndTime:   start.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"site_id = $1",
		"client_ip = $2",
		"category = $3",
		"action = $4",
		"trace_id = $5",
		"timestamp >= $6",
		"timestamp <= $7",
		"tags @> $8::jsonb",
	} {
		if !strings.Contains(where, want) {
			t.Fatalf("where clause %q missing %q", where, want)
		}
	}
	if len(args) != 8 {
		t.Fatalf("expected 8 args, got %d", len(args))
	}
}

func TestPostgreSQLIndexName(t *testing.T) {
	if got := indexName(`"public"."cheesewaf_logs"`, "timestamp"); got != `"public_cheesewaf_logs_timestamp_idx"` {
		t.Fatalf("unexpected index name %q", got)
	}
}
