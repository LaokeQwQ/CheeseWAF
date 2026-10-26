package duckdb

import (
	"context"
	"strings"
	"testing"
	"time"
)

func testTemplate(t *testing.T) Template {
	t.Helper()
	template, err := LoadTemplate("duckdb-template:security-summary-v1", []byte(`SELECT occurred_at, event_type, site_ref, route_ref, subject_hash, severity, evidence_refs, "count"
FROM audit_events
WHERE occurred_at >= ? AND occurred_at < ?
ORDER BY occurred_at
LIMIT 10000`))
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func TestLoadTemplateRejectsArbitrarySQL(t *testing.T) {
	for _, sql := range []string{
		`ATTACH 'x.db' AS x`,
		`COPY audit_events TO '/tmp/leak.csv'`,
		`SELECT * FROM read_parquet('/tmp/secret.parquet')`,
		`SELECT * FROM audit_events; DROP TABLE audit_events`,
	} {
		if _, err := LoadTemplate("bad", []byte(sql)); err == nil {
			t.Fatalf("accepted forbidden SQL %q", sql)
		}
	}
}

type fakeExecutor struct {
	sql      string
	maxBytes int
	rows     []byte
	err      error
}

func (f *fakeExecutor) Query(_ context.Context, sql string, maxBytes int) ([]byte, error) {
	f.sql = sql
	f.maxBytes = maxBytes
	return f.rows, f.err
}

func testJob(template Template) Job {
	return Job{
		SnapshotRef: "snapshot-1", SnapshotManifestSHA256: strings.Repeat("b", 64),
		SnapshotPaths: []string{"/sandbox/snapshot/a.parquet"},
		Template:      template, WindowFrom: time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC),
		WindowTo: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC), EngineVersion: "1.3.0",
		ExecutionProfileRef: "duckdb-read-only-snapshot-v1", ExecutionProfileSHA256: strings.Repeat("c", 64),
		PluginID: "duckdb-analysis", PluginVersion: "1.0.0",
	}
}

func TestRunnerBuildsBoundedRecord(t *testing.T) {
	executor := &fakeExecutor{rows: []byte(`[{"occurred_at":"2026-10-24T12:00:00Z","event_type":"auth_failure","site_ref":"site-1","route_ref":"/login","subject_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","severity":"high","evidence_refs":["evidence:e1"],"count":3}]`)}
	runner := NewRunner(executor)
	job := testJob(testTemplate(t))
	record, err := runner.Run(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if record.PluginID != job.PluginID || len(record.Findings) != 1 || record.Findings[0].Severity != "high" {
		t.Fatalf("record = %#v", record)
	}
	if !strings.Contains(executor.sql, "read_parquet(['/sandbox/snapshot/a.parquet'])") {
		t.Fatalf("SQL = %s", executor.sql)
	}
	if !strings.Contains(executor.sql, "TIMESTAMP '2026-10-24T11:00:00Z'") {
		t.Fatalf("window not bound: %s", executor.sql)
	}
	if got := countTopLevelWith(executor.sql); got != 1 {
		t.Fatalf("top-level WITH clauses = %d, want 1: %s", got, executor.sql)
	}
	if executor.maxBytes != job.Template.MaxBytes {
		t.Fatalf("executor limit = %d, want %d", executor.maxBytes, job.Template.MaxBytes)
	}
}

// Finding 11: LoadTemplate accepts templates that start with WITH. Appending
// such a body after the audit_events CTE produced two peer WITH clauses, which
// DuckDB rejects. The bound body must be composed so the final statement keeps
// exactly one top-level WITH and both window parameters are already bound.
func TestRunnerComposesLeadingWithTemplate(t *testing.T) {
	executor := &fakeExecutor{rows: []byte(`[{"severity":"high","count":2}]`)}
	template, err := LoadTemplate("duckdb-template:with-summary-v1", []byte(`WITH summary AS (
	SELECT event_type, severity FROM audit_events
	WHERE occurred_at >= ? AND occurred_at < ?
)
SELECT * FROM summary`))
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewRunner(executor).Run(context.Background(), testJob(template))
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Findings) != 1 || record.Findings[0].Severity != "high" {
		t.Fatalf("record = %#v", record)
	}
	if got := countTopLevelWith(executor.sql); got != 1 {
		t.Fatalf("top-level WITH clauses = %d, want 1: %s", got, executor.sql)
	}
	if strings.Contains(executor.sql, "?") {
		t.Fatalf("unbound placeholder left in SQL: %s", executor.sql)
	}
	if !strings.Contains(executor.sql, "TIMESTAMP '2026-10-24T11:00:00Z'") || !strings.Contains(executor.sql, "TIMESTAMP '2026-10-24T12:00:00Z'") {
		t.Fatalf("window not bound: %s", executor.sql)
	}
	if strings.Contains(executor.sql, "audit_events AS (SELECT * FROM read_parquet") == false {
		t.Fatalf("host CTE missing: %s", executor.sql)
	}
}

// countTopLevelWith counts WITH keywords outside parentheses, so a nested CTE
// inside the template body does not count as a second top-level clause.
func countTopLevelWith(sql string) int {
	upper := strings.ToUpper(sql)
	depth, count := 0, 0
	for i := range len(upper) {
		switch upper[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth != 0 || i+len("WITH") > len(upper) || upper[i:i+len("WITH")] != "WITH" {
			continue
		}
		beforeOK := i == 0 || !isSQLWordByte(upper[i-1])
		afterOK := i+len("WITH") == len(upper) || !isSQLWordByte(upper[i+len("WITH")])
		if beforeOK && afterOK {
			count++
		}
	}
	return count
}

func isSQLWordByte(b byte) bool {
	return b == '_' || b == '"' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}
