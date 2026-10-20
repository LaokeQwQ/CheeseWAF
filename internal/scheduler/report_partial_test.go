package scheduler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const partialReportWarning = "Warning: This report is incomplete because the log scan limit was reached. Counts reflect only scanned entries; matching events may be missing."

func TestRenderSecurityReportWarnsWhenPartial(t *testing.T) {
	for _, format := range []string{"", "markdown", "md", "text", "html"} {
		t.Run(format, func(t *testing.T) {
			summary := ReportSummary{Period: "daily", Total: 2, Partial: true}
			report := string(RenderSecurityReport(summary, format))
			warningAt := strings.Index(report, partialReportWarning)
			if warningAt < 0 || warningAt > strings.Index(report, "- Total events:") {
				t.Fatalf("partial counts lack a preceding incomplete-report warning: %s", report)
			}
			summary.Partial = false
			if complete := string(RenderSecurityReport(summary, format)); strings.Contains(complete, partialReportWarning) {
				t.Fatalf("complete report has an incomplete-report warning: %s", complete)
			}
		})
	}
}

func TestRenderSecurityReportJSONKeepsStructuredPartialFlag(t *testing.T) {
	for _, partial := range []bool{false, true} {
		raw := RenderSecurityReport(ReportSummary{Period: "daily", Total: 2, Partial: partial}, "json")
		var decoded ReportSummary
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("JSON report changed format: %v\n%s", err, raw)
		}
		if decoded.Partial != partial || decoded.Total != 2 || strings.Contains(string(raw), partialReportWarning) {
			t.Fatalf("JSON partial status changed: %s", raw)
		}
	}
}

func TestSecurityReportWarnsWhenOldEntriesExhaustScanBeforeRecentEvent(t *testing.T) {
	now := time.Date(2026, 5, 24, 8, 0, 0, 0, time.UTC)
	old := `{"timestamp":"2026-05-01T00:00:00Z"}` + "\n"
	recent := `{"timestamp":"2026-05-24T07:00:00Z","action":"block","category":"sqli"}` + "\n"
	raw := strings.Repeat(old, reportMaxScanLines) + recent
	if len(raw) >= reportMaxScanBytes {
		t.Fatal("fixture must reach the line limit before the byte limit")
	}
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := SummarizeSecurityLogs(path, "daily", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Partial || summary.Total != 0 {
		t.Fatalf("expected bounded scan to leave the recent event unread: partial=%t total=%d", summary.Partial, summary.Total)
	}
	report := string(RenderSecurityReport(summary, "markdown"))
	if !strings.Contains(report, partialReportWarning) {
		t.Fatalf("empty partial daily report hides unread matching events: %s", report)
	}
}
