package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		{
			Timestamp:  now.Add(-time.Hour),
			TraceID:    "cw-sqli-1",
			SiteID:     "portal",
			ClientIP:   "203.0.113.10",
			Method:     http.MethodGet,
			URI:        "/search?q=1%20or%201=1",
			StatusCode: http.StatusForbidden,
			Action:     "block",
			DetectorID: "semantic.sqli",
			Category:   "sqli",
			Severity:   "critical",
			Country:    "US",
			Message:    "SQL tautology detected",
		},
		{
			Timestamp:  now.Add(-2 * time.Hour),
			TraceID:    "cw-xss-log",
			SiteID:     "docs",
			ClientIP:   "203.0.113.10",
			Method:     http.MethodPost,
			URI:        "/docs",
			StatusCode: http.StatusOK,
			Action:     "log",
			DetectorID: "semantic.xss",
			Category:   "xss",
			Severity:   "medium",
			Country:    "US",
		},
		{
			Timestamp:  now.Add(-3 * time.Hour),
			TraceID:    "cw-bot-1",
			ClientIP:   "198.51.100.8",
			Method:     http.MethodGet,
			URI:        "/admin",
			StatusCode: http.StatusForbidden,
			Action:     "challenge",
			DetectorID: "bot.challenge",
			Category:   "bot",
			Severity:   "high",
			Country:    "DE",
		},
		{
			Timestamp:  now.Add(-4 * time.Hour),
			ClientIP:   "192.0.2.10",
			Method:     http.MethodGet,
			URI:        "/assets/app.js",
			StatusCode: http.StatusOK,
			Action:     "pass",
		},
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
	if summary.Total != 4 || summary.SecurityEvents != 3 || summary.Blocked != 1 || summary.Challenged != 1 || summary.Logged != 1 || summary.Passed != 1 || summary.UniqueIPs != 3 {
		t.Fatalf("unexpected totals: %+v", summary)
	}
	if summary.ByCategory["sqli"] != 1 || summary.ByAction["challenge"] != 1 || summary.BySeverity["critical"] != 1 || summary.BySite["portal"] != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if summary.TopIPs["203.0.113.10"] != 2 || summary.TopIPs["192.0.2.10"] != 0 || summary.TopURIs["/admin"] != 1 || summary.TopURIs["/assets/app.js"] != 0 || summary.TopDetectors["semantic.sqli"] != 1 || summary.ByCountry["US"] != 2 {
		t.Fatalf("unexpected ranked fields: %+v", summary)
	}
	if len(summary.RecentHighRisk) != 2 || summary.RecentHighRisk[0].TraceID != "cw-sqli-1" || summary.RecentHighRisk[1].TraceID != "cw-bot-1" {
		t.Fatalf("unexpected high-risk events: %+v", summary.RecentHighRisk)
	}
	report := string(RenderSecurityReport(summary, "markdown"))
	if !strings.Contains(report, "CheeseWAF Security Daily Report") {
		t.Fatalf("unexpected report: %s", report)
	}
	for _, want := range []string{"Security events: 3", "Unique source IPs: 3", "Challenge events: 1", "Top requested URIs", "/search?q=1%20or%201=1", "Recent High-risk Events", "cw-sqli-1"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q: %s", want, report)
		}
	}
	if strings.Contains(report, "/assets/app.js") {
		t.Fatalf("normal pass traffic leaked into security ranking: %s", report)
	}
}

func TestSecurityReportWeeklyWindowAndJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	now := time.Date(2026, 5, 24, 8, 0, 0, 0, time.UTC)
	entries := []storage.LogEntry{
		{Timestamp: now.Add(-6 * 24 * time.Hour), Action: "block", Category: "ssrf", Severity: "high", ClientIP: "203.0.113.30"},
		{Timestamp: now.Add(-8 * 24 * time.Hour), Action: "block", Category: "sqli", Severity: "critical", ClientIP: "203.0.113.31"},
	}
	writeLogEntries(t, path, entries)
	summary, err := SummarizeSecurityLogs(path, "weekly", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 || summary.ByCategory["ssrf"] != 1 || summary.ByCategory["sqli"] != 0 {
		t.Fatalf("unexpected weekly summary: %+v", summary)
	}
	raw := RenderSecurityReport(summary, "json")
	var decoded ReportSummary
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json report did not unmarshal: %v\n%s", err, raw)
	}
	if decoded.Period != "weekly" || decoded.Total != 1 || decoded.WindowStart.IsZero() || decoded.WindowEnd.IsZero() {
		t.Fatalf("unexpected decoded report: %+v", decoded)
	}
}

func TestSecurityReportWritesJSONFileAndWebhookContentType(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	writeLogEntries(t, logPath, []storage.LogEntry{{
		Timestamp: time.Now().UTC().Add(-time.Minute),
		Action:    "block",
		Category:  "sqli",
		Severity:  "critical",
		ClientIP:  "203.0.113.44",
	}})
	reportsDir := filepath.Join(dir, "reports")
	err := SecurityReport(logPath, dir)(context.Background(), Task{
		ID:        "security/daily",
		Type:      "security_report",
		Channel:   "file",
		Recipient: reportsDir,
		Period:    "daily",
		Format:    "json",
	})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(reportsDir, "security-daily-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one json report, got %v", matches)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Fatalf("unexpected content type: %s", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	err = SecurityReport(logPath, dir)(context.Background(), Task{
		ID:        "security-weekly",
		Type:      "security_report",
		Channel:   "webhook",
		Recipient: server.URL,
		Period:    "weekly",
		Format:    "json",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeLogEntries(t *testing.T, path string, entries []storage.LogEntry) {
	t.Helper()
	var raw []byte
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
}
