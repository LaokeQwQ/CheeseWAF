package scheduler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type ReportSummary struct {
	GeneratedAt    time.Time      `json:"generated_at"`
	Period         string         `json:"period"`
	WindowStart    time.Time      `json:"window_start"`
	WindowEnd      time.Time      `json:"window_end"`
	Total          int            `json:"total"`
	SecurityEvents int            `json:"security_events"`
	Blocked        int            `json:"blocked"`
	Challenged     int            `json:"challenged"`
	Logged         int            `json:"logged"`
	Passed         int            `json:"passed"`
	UniqueIPs      int            `json:"unique_ips"`
	ByAction       map[string]int `json:"by_action"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCategory     map[string]int `json:"by_category"`
	BySite         map[string]int `json:"by_site"`
	ByCountry      map[string]int `json:"by_country"`
	TopIPs         map[string]int `json:"top_ips"`
	TopURIs        map[string]int `json:"top_uris"`
	TopDetectors   map[string]int `json:"top_detectors"`
	RecentHighRisk []ReportEvent  `json:"recent_high_risk"`
}

type ReportEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	TraceID    string    `json:"trace_id,omitempty"`
	SiteID     string    `json:"site_id,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	Method     string    `json:"method,omitempty"`
	URI        string    `json:"uri,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	Action     string    `json:"action,omitempty"`
	DetectorID string    `json:"detector_id,omitempty"`
	Category   string    `json:"category,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Country    string    `json:"country,omitempty"`
	Message    string    `json:"message,omitempty"`
}

func SecurityReport(logPath, dataDir string) TaskFunc {
	return func(ctx context.Context, task Task) error {
		if task.Period == "" {
			task.Period = task.Frequency
		}
		if task.Period == "" {
			task.Period = "daily"
		}
		if task.Format == "" {
			task.Format = "markdown"
		}
		if task.Channel == "" {
			task.Channel = "file"
		}
		if task.Recipient == "" {
			task.Recipient = filepath.Join(dataDir, "reports")
		}
		summary, err := SummarizeSecurityLogs(logPath, task.Period, time.Now)
		if err != nil {
			return err
		}
		report := RenderSecurityReport(summary, task.Format)
		switch task.Channel {
		case "webhook":
			return postReport(ctx, task.Recipient, task.Format, report)
		default:
			return writeReport(task.Recipient, task.ID, task.Format, report)
		}
	}
}

func SummarizeSecurityLogs(logPath, period string, nowFn func() time.Time) (ReportSummary, error) {
	now := nowFn().UTC()
	since := now.Add(-24 * time.Hour)
	if period == "weekly" {
		since = now.Add(-7 * 24 * time.Hour)
	}
	summary := ReportSummary{
		GeneratedAt:  now,
		Period:       period,
		WindowStart:  since,
		WindowEnd:    now,
		ByAction:     map[string]int{},
		BySeverity:   map[string]int{},
		ByCategory:   map[string]int{},
		BySite:       map[string]int{},
		ByCountry:    map[string]int{},
		TopIPs:       map[string]int{},
		TopURIs:      map[string]int{},
		TopDetectors: map[string]int{},
	}
	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return summary, nil
		}
		return summary, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	seenIPs := map[string]struct{}{}
	for scanner.Scan() {
		var entry storage.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Timestamp.Before(since) || entry.Timestamp.After(now.Add(time.Minute)) {
			continue
		}
		summary.Total++
		action := normalizedOr(entry.Action, "pass")
		summary.ByAction[action]++
		securityEvent := isSecurityReportEntry(entry, action)
		if securityEvent {
			summary.SecurityEvents++
		}
		switch action {
		case "block":
			summary.Blocked++
		case "challenge":
			summary.Challenged++
		case "log":
			summary.Logged++
		case "pass":
			summary.Passed++
		}
		severity := normalizedOr(entry.Severity, "info")
		if entry.ClientIP != "" {
			seenIPs[entry.ClientIP] = struct{}{}
		}
		if securityEvent {
			summary.BySeverity[severity]++
			if category := normalizedOr(entry.Category, "uncategorized"); category != "" {
				summary.ByCategory[category]++
			}
			if entry.ClientIP != "" {
				summary.TopIPs[entry.ClientIP]++
			}
			if entry.URI != "" {
				summary.TopURIs[entry.URI]++
			}
			if entry.SiteID != "" {
				summary.BySite[entry.SiteID]++
			}
			if entry.Country != "" {
				summary.ByCountry[strings.ToUpper(strings.TrimSpace(entry.Country))]++
			}
			if entry.DetectorID != "" {
				summary.TopDetectors[entry.DetectorID]++
			}
		}
		if isHighRiskReportEvent(action, severity) {
			summary.RecentHighRisk = append(summary.RecentHighRisk, reportEventFromLog(entry, action, severity))
		}
	}
	summary.UniqueIPs = len(seenIPs)
	sort.Slice(summary.RecentHighRisk, func(i, j int) bool {
		return summary.RecentHighRisk[i].Timestamp.After(summary.RecentHighRisk[j].Timestamp)
	})
	if len(summary.RecentHighRisk) > 10 {
		summary.RecentHighRisk = summary.RecentHighRisk[:10]
	}
	return summary, scanner.Err()
}

func RenderSecurityReport(summary ReportSummary, format string) []byte {
	if format == "json" {
		data, _ := json.MarshalIndent(summary, "", "  ")
		return data
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# CheeseWAF Security %s Report\n\n", reportTitle(summary.Period))
	fmt.Fprintf(&buf, "- Generated: %s\n", summary.GeneratedAt.Format(time.RFC3339))
	if !summary.WindowStart.IsZero() && !summary.WindowEnd.IsZero() {
		fmt.Fprintf(&buf, "- Window: %s to %s\n", summary.WindowStart.Format(time.RFC3339), summary.WindowEnd.Format(time.RFC3339))
	}
	fmt.Fprintf(&buf, "- Total events: %d\n", summary.Total)
	fmt.Fprintf(&buf, "- Security events: %d\n", summary.SecurityEvents)
	fmt.Fprintf(&buf, "- Unique source IPs: %d\n", summary.UniqueIPs)
	fmt.Fprintf(&buf, "- Blocked events: %d\n", summary.Blocked)
	fmt.Fprintf(&buf, "- Challenge events: %d\n", summary.Challenged)
	fmt.Fprintf(&buf, "- Logged-only detections: %d\n\n", summary.Logged)
	writeRankedMap(&buf, "Actions", summary.ByAction, 10)
	writeRankedMap(&buf, "Severities", summary.BySeverity, 10)
	writeRankedMap(&buf, "Categories", summary.ByCategory, 10)
	writeRankedMap(&buf, "Top source IPs", summary.TopIPs, 10)
	writeRankedMap(&buf, "Top requested URIs", summary.TopURIs, 10)
	writeRankedMap(&buf, "Top detectors", summary.TopDetectors, 10)
	writeRankedMap(&buf, "Countries", summary.ByCountry, 10)
	writeHighRiskEvents(&buf, summary.RecentHighRisk)
	return buf.Bytes()
}

func reportTitle(period string) string {
	if period == "" {
		return "Daily"
	}
	return strings.ToUpper(period[:1]) + period[1:]
}

func writeRankedMap(w io.Writer, title string, values map[string]int, limit int) {
	fmt.Fprintf(w, "## %s\n\n", title)
	if len(values) == 0 {
		fmt.Fprintln(w, "No data.")
		fmt.Fprintln(w)
		return
	}
	type item struct {
		key   string
		count int
	}
	var items []item
	for key, count := range values {
		items = append(items, item{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].key < items[j].key
		}
		return items[i].count > items[j].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	for _, item := range items {
		fmt.Fprintf(w, "- %s: %d\n", item.key, item.count)
	}
	fmt.Fprintln(w)
}

func writeHighRiskEvents(w io.Writer, events []ReportEvent) {
	fmt.Fprintln(w, "## Recent High-risk Events")
	fmt.Fprintln(w)
	if len(events) == 0 {
		fmt.Fprintln(w, "No data.")
		fmt.Fprintln(w)
		return
	}
	for _, event := range events {
		parts := []string{
			event.Timestamp.Format(time.RFC3339),
			trimReportField(event.Action),
			trimReportField(event.Severity),
			trimReportField(event.Category),
			trimReportField(event.ClientIP),
			trimReportField(event.Method),
			trimReportField(event.URI),
		}
		fmt.Fprintf(w, "- %s\n", strings.Join(compact(parts), " | "))
		if event.Message != "" {
			fmt.Fprintf(w, "  - %s\n", trimReportField(event.Message))
		}
		if event.TraceID != "" {
			fmt.Fprintf(w, "  - trace: `%s`\n", trimReportField(event.TraceID))
		}
	}
	fmt.Fprintln(w)
}

func writeReport(dir, taskID, format string, report []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s%s", safeReportID(taskID), time.Now().UTC().Format("20060102-150405"), reportExtension(format))
	return os.WriteFile(filepath.Join(dir, name), report, 0o640)
}

func postReport(ctx context.Context, endpoint, format string, report []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(report))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", reportContentType(format))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func normalizedOr(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func isHighRiskReportEvent(action, severity string) bool {
	switch action {
	case "block", "challenge":
		return true
	}
	switch severity {
	case "critical", "high":
		return true
	default:
		return false
	}
}

func isSecurityReportEntry(entry storage.LogEntry, action string) bool {
	if action != "pass" && action != "cache_hit" && action != "redirect" {
		return true
	}
	return strings.TrimSpace(entry.Category) != "" ||
		strings.TrimSpace(entry.DetectorID) != "" ||
		strings.TrimSpace(entry.Severity) != "" ||
		strings.TrimSpace(entry.Message) != ""
}

func reportEventFromLog(entry storage.LogEntry, action, severity string) ReportEvent {
	return ReportEvent{
		Timestamp:  entry.Timestamp.UTC(),
		TraceID:    entry.TraceID,
		SiteID:     entry.SiteID,
		ClientIP:   entry.ClientIP,
		Method:     entry.Method,
		URI:        entry.URI,
		StatusCode: entry.StatusCode,
		Action:     action,
		DetectorID: entry.DetectorID,
		Category:   normalizedOr(entry.Category, "uncategorized"),
		Severity:   severity,
		Country:    strings.ToUpper(strings.TrimSpace(entry.Country)),
		Message:    entry.Message,
	}
}

func compact(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func trimReportField(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if len(value) > 180 {
		return value[:177] + "..."
	}
	return value
}

func safeReportID(taskID string) string {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return "security-report"
	}
	var b strings.Builder
	for _, r := range taskID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "security-report"
	}
	return b.String()
}

func reportExtension(format string) string {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return ".json"
	}
	return ".md"
}

func reportContentType(format string) string {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return "application/json; charset=utf-8"
	}
	return "text/markdown; charset=utf-8"
}
