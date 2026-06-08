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
	GeneratedAt time.Time      `json:"generated_at"`
	Period      string         `json:"period"`
	Total       int            `json:"total"`
	Blocked     int            `json:"blocked"`
	ByCategory  map[string]int `json:"by_category"`
	TopIPs      map[string]int `json:"top_ips"`
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
			return postReport(ctx, task.Recipient, report)
		default:
			return writeReport(task.Recipient, task.ID, report)
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
		GeneratedAt: now,
		Period:      period,
		ByCategory:  map[string]int{},
		TopIPs:      map[string]int{},
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
	for scanner.Scan() {
		var entry storage.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Timestamp.Before(since) || entry.Timestamp.After(now.Add(time.Minute)) {
			continue
		}
		summary.Total++
		if entry.Action == "block" {
			summary.Blocked++
		}
		if entry.Category != "" {
			summary.ByCategory[entry.Category]++
		}
		if entry.ClientIP != "" {
			summary.TopIPs[entry.ClientIP]++
		}
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
	fmt.Fprintf(&buf, "- Total events: %d\n", summary.Total)
	fmt.Fprintf(&buf, "- Blocked events: %d\n\n", summary.Blocked)
	writeRankedMap(&buf, "Categories", summary.ByCategory)
	writeRankedMap(&buf, "Top source IPs", summary.TopIPs)
	return buf.Bytes()
}

func reportTitle(period string) string {
	if period == "" {
		return "Daily"
	}
	return strings.ToUpper(period[:1]) + period[1:]
}

func writeRankedMap(w io.Writer, title string, values map[string]int) {
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
		return items[i].count > items[j].count
	})
	for _, item := range items {
		fmt.Fprintf(w, "- %s: %d\n", item.key, item.count)
	}
	fmt.Fprintln(w)
}

func writeReport(dir, taskID string, report []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s.md", taskID, time.Now().UTC().Format("20060102-150405"))
	return os.WriteFile(filepath.Join(dir, name), report, 0o640)
}

func postReport(ctx context.Context, endpoint string, report []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(report))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/markdown; charset=utf-8")
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
