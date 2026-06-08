package scheduler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestSecurityReportSummarizesLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	now := time.Date(2026, 5, 24, 8, 0, 0, 0, time.UTC)
	entries := []storage.LogEntry{
		{Timestamp: now.Add(-time.Hour), Action: "block", Category: "sqli", ClientIP: "203.0.113.10"},
		{Timestamp: now.Add(-2 * time.Hour), Action: "pass", Category: "xss", ClientIP: "203.0.113.10"},
		{Timestamp: now.Add(-48 * time.Hour), Action: "block", Category: "rce", ClientIP: "198.51.100.4"},
	}
	var raw []byte
	for _, entry := range entries {
		line, _ := json.Marshal(entry)
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	summary, err := SummarizeSecurityLogs(path, "daily", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 2 || summary.Blocked != 1 || summary.ByCategory["sqli"] != 1 || summary.TopIPs["203.0.113.10"] != 2 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	report := string(RenderSecurityReport(summary, "markdown"))
	if !strings.Contains(report, "CheeseWAF Security Daily Report") {
		t.Fatalf("unexpected report: %s", report)
	}
}
