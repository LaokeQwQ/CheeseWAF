package scheduler

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"math/bits"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	reportLowCardinalityLimit = 64
	reportTopKCapacity        = 1024
	reportExactIPLimit        = 4096
	reportHLLPrecision        = 10
	reportRecentRiskLimit     = 10
)

var reportHTTPClient = netguard.NewHTTPClient(netguard.HTTPClientOptions{
	Timeout: 15 * time.Second,
	Policy:  reportWebhookURLPolicy(),
})

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

type reportCounterItem struct {
	key   string
	count int
	index int
}

type reportCounterHeap []*reportCounterItem

func (h reportCounterHeap) Len() int { return len(h) }
func (h reportCounterHeap) Less(i, j int) bool {
	if h[i].count == h[j].count {
		return h[i].key > h[j].key
	}
	return h[i].count < h[j].count
}
func (h reportCounterHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *reportCounterHeap) Push(value any) {
	item := value.(*reportCounterItem)
	item.index = len(*h)
	*h = append(*h, item)
}
func (h *reportCounterHeap) Pop() any {
	old := *h
	item := old[len(old)-1]
	item.index = -1
	*h = old[:len(old)-1]
	return item
}

type boundedCounter struct {
	limit int
	items map[string]*reportCounterItem
	heap  reportCounterHeap
}

func newBoundedCounter(limit int) *boundedCounter {
	if limit <= 0 {
		limit = 1
	}
	return &boundedCounter{limit: limit, items: make(map[string]*reportCounterItem, limit)}
}

func (c *boundedCounter) Add(raw string) {
	key := boundedReportKey(raw, 512)
	if key == "" {
		return
	}
	if item := c.items[key]; item != nil {
		item.count++
		heap.Fix(&c.heap, item.index)
		return
	}
	if len(c.items) < c.limit {
		item := &reportCounterItem{key: key, count: 1}
		c.items[key] = item
		heap.Push(&c.heap, item)
		return
	}
	minimum := c.heap[0]
	delete(c.items, minimum.key)
	minimum.key = key
	minimum.count++
	c.items[key] = minimum
	heap.Fix(&c.heap, 0)
}

func (c *boundedCounter) Values() map[string]int {
	values := make(map[string]int, len(c.items))
	for key, item := range c.items {
		values[key] = item.count
	}
	return values
}

type uniqueIPCounter struct {
	exactLimit int
	exact      map[string]struct{}
	registers  []uint8
}

func newUniqueIPCounter(exactLimit int) *uniqueIPCounter {
	if exactLimit <= 0 {
		exactLimit = 1
	}
	return &uniqueIPCounter{exactLimit: exactLimit, exact: make(map[string]struct{}, exactLimit)}
}

func (c *uniqueIPCounter) Add(raw string) {
	value := boundedReportKey(raw, 256)
	if value == "" {
		return
	}
	if c.exact != nil {
		if _, exists := c.exact[value]; exists {
			return
		}
		if len(c.exact) < c.exactLimit {
			c.exact[value] = struct{}{}
			return
		}
		c.registers = make([]uint8, 1<<reportHLLPrecision)
		for existing := range c.exact {
			c.addApproximate(existing)
		}
		c.exact = nil
	}
	c.addApproximate(value)
}

func (c *uniqueIPCounter) addApproximate(value string) {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(value))
	hash := hasher.Sum64()
	index := int(hash >> (64 - reportHLLPrecision))
	w := hash << reportHLLPrecision
	rank := bits.LeadingZeros64(w) + 1
	maxRank := 64 - reportHLLPrecision + 1
	if rank > maxRank {
		rank = maxRank
	}
	if uint8(rank) > c.registers[index] {
		c.registers[index] = uint8(rank)
	}
}

func (c *uniqueIPCounter) Count() int {
	if c.exact != nil {
		return len(c.exact)
	}
	m := float64(len(c.registers))
	sum := 0.0
	zeros := 0
	for _, register := range c.registers {
		sum += math.Pow(2, -float64(register))
		if register == 0 {
			zeros++
		}
	}
	estimate := 0.7213 / (1 + 1.079/m) * m * m / sum
	if zeros > 0 && estimate <= 2.5*m {
		estimate = m * math.Log(m/float64(zeros))
	}
	if estimate < 0 {
		return 0
	}
	return int(math.Round(estimate))
}

func boundedReportKey(value string, maxBytes int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if len(value) <= maxBytes {
		return value
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(value))
	keep := maxBytes - 17
	if keep < 0 {
		keep = 0
	}
	for keep > 0 && keep < len(value) && value[keep]&0xc0 == 0x80 {
		keep--
	}
	return fmt.Sprintf("%s#%016x", value[:keep], hasher.Sum64())
}

func addRecentHighRisk(events []ReportEvent, event ReportEvent, limit int) []ReportEvent {
	if limit <= 0 {
		return events[:0]
	}
	if len(events) < limit {
		return append(events, event)
	}
	oldest := 0
	for index := 1; index < len(events); index++ {
		if events[index].Timestamp.Before(events[oldest].Timestamp) {
			oldest = index
		}
	}
	if event.Timestamp.After(events[oldest].Timestamp) {
		events[oldest] = event
	}
	return events
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
		summary, err := SummarizeSecurityLogsContext(ctx, logPath, task.Period, time.Now)
		if err != nil {
			return err
		}
		report := RenderSecurityReport(summary, task.Format)
		if err := ctx.Err(); err != nil {
			return err
		}
		switch task.Channel {
		case "webhook":
			return postReport(ctx, task.Recipient, task.Format, report)
		default:
			return writeReport(task.Recipient, task.ID, task.Format, report)
		}
	}
}

func SummarizeSecurityLogs(logPath, period string, nowFn func() time.Time) (ReportSummary, error) {
	return SummarizeSecurityLogsContext(context.Background(), logPath, period, nowFn)
}

func SummarizeSecurityLogsContext(ctx context.Context, logPath, period string, nowFn func() time.Time) (ReportSummary, error) {
	now := nowFn().UTC()
	since := now.Add(-24 * time.Hour)
	if period == "weekly" {
		since = now.Add(-7 * 24 * time.Hour)
	} else if period == "monthly" {
		since = now.Add(-30 * 24 * time.Hour)
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
	uniqueIPs := newUniqueIPCounter(reportExactIPLimit)
	byAction := newBoundedCounter(reportLowCardinalityLimit)
	bySeverity := newBoundedCounter(reportLowCardinalityLimit)
	byCategory := newBoundedCounter(reportTopKCapacity)
	bySite := newBoundedCounter(reportTopKCapacity)
	byCountry := newBoundedCounter(reportLowCardinalityLimit)
	topIPs := newBoundedCounter(reportTopKCapacity)
	topURIs := newBoundedCounter(reportTopKCapacity)
	topDetectors := newBoundedCounter(reportTopKCapacity)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
		var entry storage.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Timestamp.Before(since) || entry.Timestamp.After(now.Add(time.Minute)) {
			continue
		}
		summary.Total++
		action := normalizedOr(entry.Action, "pass")
		byAction.Add(action)
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
			uniqueIPs.Add(entry.ClientIP)
		}
		if securityEvent {
			bySeverity.Add(severity)
			if category := normalizedOr(entry.Category, "uncategorized"); category != "" {
				byCategory.Add(category)
			}
			if entry.ClientIP != "" {
				topIPs.Add(entry.ClientIP)
			}
			if entry.URI != "" {
				topURIs.Add(entry.URI)
			}
			if entry.SiteID != "" {
				bySite.Add(entry.SiteID)
			}
			if entry.Country != "" {
				byCountry.Add(strings.ToUpper(strings.TrimSpace(entry.Country)))
			}
			if entry.DetectorID != "" {
				topDetectors.Add(entry.DetectorID)
			}
		}
		if isHighRiskReportEvent(action, severity) {
			summary.RecentHighRisk = addRecentHighRisk(summary.RecentHighRisk, reportEventFromLog(entry, action, severity), reportRecentRiskLimit)
		}
	}
	summary.UniqueIPs = uniqueIPs.Count()
	summary.ByAction = byAction.Values()
	summary.BySeverity = bySeverity.Values()
	summary.ByCategory = byCategory.Values()
	summary.BySite = bySite.Values()
	summary.ByCountry = byCountry.Values()
	summary.TopIPs = topIPs.Values()
	summary.TopURIs = topURIs.Values()
	summary.TopDetectors = topDetectors.Values()
	sort.Slice(summary.RecentHighRisk, func(i, j int) bool {
		return summary.RecentHighRisk[i].Timestamp.After(summary.RecentHighRisk[j].Timestamp)
	})
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
	resp, err := reportHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = netguard.DrainAndClose(resp.Body) }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func reportWebhookURLPolicy() netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "security report webhook",
		HostPurpose:    "security report webhook",
		AllowedSchemes: []string{"https"},
	}
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
		TraceID:    trimReportField(entry.TraceID),
		SiteID:     trimReportField(entry.SiteID),
		ClientIP:   trimReportField(entry.ClientIP),
		Method:     trimReportField(entry.Method),
		URI:        trimReportField(entry.URI),
		StatusCode: entry.StatusCode,
		Action:     trimReportField(action),
		DetectorID: trimReportField(entry.DetectorID),
		Category:   trimReportField(normalizedOr(entry.Category, "uncategorized")),
		Severity:   trimReportField(severity),
		Country:    trimReportField(strings.ToUpper(strings.TrimSpace(entry.Country))),
		Message:    trimReportField(entry.Message),
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
