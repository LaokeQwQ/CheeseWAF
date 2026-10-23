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
	sql  string
	rows []byte
	err  error
}

func (f *fakeExecutor) Query(_ context.Context, sql string) ([]byte, error) {
	f.sql = sql
	return f.rows, f.err
}

func TestRunnerBuildsBoundedRecord(t *testing.T) {
	executor := &fakeExecutor{rows: []byte(`[{"occurred_at":"2026-10-24T12:00:00Z","event_type":"auth_failure","site_ref":"site-1","route_ref":"/login","subject_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","severity":"high","evidence_refs":["evidence:e1"],"count":3}]`)}
	runner := NewRunner(executor)
	job := Job{
		SnapshotRef: "snapshot-1", SnapshotManifestSHA256: strings.Repeat("b", 64),
		SnapshotPaths: []string{"/sandbox/snapshot/a.parquet"},
		Template:      testTemplate(t), WindowFrom: time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC),
		WindowTo: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC), EngineVersion: "1.3.0",
		ExecutionProfileRef: "duckdb-read-only-snapshot-v1", ExecutionProfileSHA256: strings.Repeat("c", 64),
		PluginID: "duckdb-analysis", PluginVersion: "1.0.0",
	}
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
}
