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

func TestPostgreSQLWhereBuildsLiteralSearchAndStableKeyset(t *testing.T) {
	stamp := time.Date(2026, 8, 22, 8, 0, 0, 123, time.UTC)
	where, args, err := postgresqlWhere(storage.LogFilter{
		Search:        `100%_literal`,
		Kind:          "security",
		WatermarkTime: stamp.Add(time.Minute),
		WatermarkID:   "z",
		BeforeTime:    stamp,
		BeforeID:      "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ILIKE $1 ESCAPE", "detector_id", "severity", "'log','monitor'", "timestamp < $2", "id < $4", "timestamp < $5", "id < $7"} {
		if !strings.Contains(where, want) {
			t.Fatalf("where clause %q missing %q", where, want)
		}
	}
	if len(args) != 7 || args[0] != `%100\%\_literal%` || args[3] != "z" || args[6] != "b" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestPostgreSQLIndexName(t *testing.T) {
	if got := indexName(`"public"."cheesewaf_logs"`, "timestamp"); got != `"public_cheesewaf_logs_timestamp_idx"` {
		t.Fatalf("unexpected index name %q", got)
	}
}

func TestPostgreSQLInsertQueryBuildsBoundedParameterizedRows(t *testing.T) {
	query, err := postgresqlInsertQuery(`"public"."cheesewaf_logs"`, 2)
	if err != nil {
		t.Fatalf("build insert query: %v", err)
	}
	for _, want := range []string{
		`INSERT INTO "public"."cheesewaf_logs"`,
		`($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::jsonb, $19::jsonb)`,
		`($20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37::jsonb, $38::jsonb)`,
		`ON CONFLICT (id) DO UPDATE SET`,
		`metadata = EXCLUDED.metadata`,
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("insert query %q missing %q", query, want)
		}
	}
	if strings.Contains(query, "$39") {
		t.Fatalf("insert query exceeded the expected placeholder range: %q", query)
	}
	if _, err := postgresqlInsertQuery(`"logs"`, postgresqlLogBatchSize+1); err == nil {
		t.Fatal("expected oversized PostgreSQL batch to be rejected")
	}
}

func TestPostgreSQLLogEntryValuesPreserveAllColumns(t *testing.T) {
	values, err := postgresqlLogEntryValues(&storage.LogEntry{
		ID:         "entry-1",
		Timestamp:  time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC),
		TraceID:    "trace-1",
		Latency:    1500 * time.Millisecond,
		Tags:       []string{"scanner"},
		Metadata:   map[string]any{"source": "test"},
		StatusCode: 403,
	})
	if err != nil {
		t.Fatalf("build values: %v", err)
	}
	if len(values) != postgresqlLogColumnCount {
		t.Fatalf("expected %d values, got %d", postgresqlLogColumnCount, len(values))
	}
	if values[0] != "entry-1" || values[7] != 403 || values[16] != 1500.0 {
		t.Fatalf("unexpected scalar values: %#v", values)
	}
	if values[17] != `["scanner"]` || values[18] != `{"source":"test"}` {
		t.Fatalf("unexpected JSON values: %#v", values[17:])
	}
}
