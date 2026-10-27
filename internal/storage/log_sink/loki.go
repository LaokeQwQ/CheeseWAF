package log_sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	// lokiDefaultJobLabel keeps every CheeseWAF stream selectable in Loki even
	// when the operator configures no labels at all.
	lokiDefaultJobLabel = "cheesewaf"
	lokiPushPath        = "/loki/api/v1/push"
	lokiQueryRangePath  = "/loki/api/v1/query_range"
	lokiQueryPath       = "/loki/api/v1/query"
	// lokiQueryPageSize is the row budget for one query_range request. Loki has
	// no offset, so paging walks the time window backwards (or forwards).
	lokiQueryPageSize = 1000
	// lokiMaxQueryPages bounds how many requests one Query may issue. Row
	// filters are applied after the fetch, so a lower cap would silently miss
	// older matches; the window itself is already bounded by the caller's
	// range and by lokiDefaultQueryWindow.
	lokiMaxQueryPages = 10
	// lokiDefaultQueryWindow bounds reads that arrive without an explicit time
	// range so a single API call cannot ask Loki for its full retention.
	lokiDefaultQueryWindow = 24 * time.Hour
	lokiMaxErrorBodyBytes  = 4096
)

// LokiSink ships access/security log entries to Grafana Loki and reads them
// back through the LogQL HTTP API.
//
// Writes use the push API: entries are grouped into streams by their label set
// (the configured static labels plus a low-cardinality dynamic `site_id` label)
// and each entry is stored as one JSON line, so the decode path can rebuild a
// storage.LogEntry without a Loki-specific schema.
//
// Reads translate the LogFilter into a LogQL selector plus line filters and
// then verify every returned row client-side with the same matcher the file
// sink uses, so a Loki hit can never widen a filter.
type LokiSink struct {
	cfg    config.LokiConfig
	base   string
	client *http.Client
	async  *asyncLogWriter
}

func NewLokiSink(cfg config.LokiConfig, client *http.Client) (*LokiSink, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("loki endpoint is required")
	}
	base, err := lokiBaseURL(endpoint)
	if err != nil {
		return nil, err
	}
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	labels := make(map[string]string, len(cfg.Labels)+1)
	for key, value := range cfg.Labels {
		labels[key] = value
	}
	if _, ok := labels["job"]; !ok {
		labels["job"] = lokiDefaultJobLabel
	}
	if err := config.ValidateLokiLabels(labels); err != nil {
		return nil, err
	}
	cfg.Labels = labels
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if client == nil {
		client = guardedLogSinkHTTPClient(cfg.Timeout, "loki endpoint", cfg.AllowPrivateEndpoint)
	}
	sink := &LokiSink{cfg: cfg, base: base, client: client}
	sink.async = newAsyncLogWriter("loki", sink.writeSync, nil, func() error {
		sink.client.CloseIdleConnections()
		return nil
	}, asyncLogWriterOptions{batchSize: remoteLogBatchSize, writeBatch: sink.writeBatchSync})
	return sink, nil
}

func (s *LokiSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if s.async == nil {
		return s.writeSync(ctx, entry)
	}
	return s.async.Write(ctx, entry)
}

func (s *LokiSink) Flush(ctx context.Context) error {
	if s.async == nil {
		return nil
	}
	return s.async.Flush(ctx)
}

func (s *LokiSink) Close() error {
	if s.async == nil {
		return nil
	}
	return s.async.Close()
}

func (s *LokiSink) AsyncStats() AsyncLogSinkStats {
	if s.async == nil {
		return AsyncLogSinkStats{}
	}
	return s.async.Stats()
}

type lokiPushPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

func (s *LokiSink) writeSync(ctx context.Context, entry *storage.LogEntry) error {
	return s.writeBatchSync(ctx, []*storage.LogEntry{entry})
}

func (s *LokiSink) writeBatchSync(ctx context.Context, entries []*storage.LogEntry) error {
	payload, err := s.buildPushPayload(entries)
	if err != nil {
		return err
	}
	if len(payload.Streams) == 0 {
		return nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode loki push payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+lokiPushPath, bytes.NewReader(data))
	if err != nil {
		return err
	}
	s.applyHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer netguard.DrainAndClose(resp.Body)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, lokiMaxErrorBodyBytes))
		return fmt.Errorf("loki returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// buildPushPayload groups entries into one stream per distinct label set. The
// stream order is deterministic so identical batches produce identical bodies.
func (s *LokiSink) buildPushPayload(entries []*storage.LogEntry) (lokiPushPayload, error) {
	streams := make(map[string]*lokiStream)
	order := make([]string, 0, len(entries))
	now := time.Now().UTC()
	var zeroStamps int
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		labels := s.entryLabels(entry)
		signature := lokiLabelSignature(labels)
		stream, ok := streams[signature]
		if !ok {
			stream = &lokiStream{Stream: labels, Values: make([][2]string, 0, 1)}
			streams[signature] = stream
			order = append(order, signature)
		}
		stamp := entry.Timestamp.UTC()
		if stamp.IsZero() {
			// Loki requires a nanosecond timestamp; offset duplicates inside a
			// batch so a burst of untimestamped entries stays unique.
			stamp = now.Add(time.Duration(zeroStamps) * time.Nanosecond)
			zeroStamps++
		}
		line, err := lokiEntryLine(entry, stamp)
		if err != nil {
			return lokiPushPayload{}, err
		}
		stream.Values = append(stream.Values, [2]string{strconv.FormatInt(stamp.UnixNano(), 10), line})
	}
	if len(order) == 0 {
		return lokiPushPayload{}, nil
	}
	sort.Strings(order)
	payload := lokiPushPayload{Streams: make([]lokiStream, 0, len(order))}
	for _, signature := range order {
		payload.Streams = append(payload.Streams, *streams[signature])
	}
	return payload, nil
}

// entryLabels returns the static labels plus a bounded dynamic site label. All
// other entry fields stay in the JSON line: Loki labels are indexed, so they
// must not carry unbounded values such as client IPs or trace IDs.
func (s *LokiSink) entryLabels(entry *storage.LogEntry) map[string]string {
	labels := make(map[string]string, len(s.cfg.Labels)+2)
	for key, value := range s.cfg.Labels {
		labels[key] = value
	}
	if _, ok := labels["job"]; !ok {
		labels["job"] = lokiDefaultJobLabel
	}
	if _, ok := labels["site_id"]; !ok && entry.SiteID != "" {
		labels["site_id"] = entry.SiteID
	}
	return labels
}

func lokiEntryLine(entry *storage.LogEntry, stamp time.Time) (string, error) {
	clone := *entry
	clone.Timestamp = stamp
	data, err := json.Marshal(&clone)
	if err != nil {
		return "", fmt.Errorf("encode loki log line: %w", err)
	}
	return string(data), nil
}

func lokiLabelSignature(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(labels[key])
		builder.WriteByte('\x00')
	}
	return builder.String()
}

func (s *LokiSink) applyHeaders(req *http.Request) {
	if s.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", s.cfg.TenantID)
	}
	if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
}

// lokiBaseURL normalizes the configured endpoint: operators may point at the
// Loki root or directly at the documented push URL.
func lokiBaseURL(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse loki endpoint: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("loki endpoint must be an absolute http(s) URL")
	}
	path := strings.TrimRight(parsed.Path, "/")
	path = strings.TrimSuffix(path, lokiPushPath)
	path = strings.TrimSuffix(path, lokiQueryRangePath)
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// Query implements storage.LogSink. Loki has no offset parameter, so the sink
// pages through the selected time window and applies the shared filter matcher,
// ordering and paging locally. A single fetch of offset+limit rows is not
// enough: filters LogQL cannot express (ID, Kind, Tags) are applied after the
// fetch, so the newest page may match nothing while older rows still do.
func (s *LokiSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	window, err := s.queryWindow(filter)
	if err != nil {
		return nil, 0, err
	}
	limit := normalizedLimit(filter.Limit)
	direction := "backward"
	if filter.Ascending {
		direction = "forward"
	}
	matched := make([]storage.LogEntry, 0, normalizedLimit(filter.Offset+limit))
	pageWindow := window
	for page := 0; page < lokiMaxQueryPages; page++ {
		rows, err := s.queryRange(ctx, pageWindow, lokiQueryPageSize, direction)
		if err != nil {
			return nil, 0, err
		}
		for _, row := range rows {
			entry, err := lokiDecodeRow(row)
			if err != nil {
				return nil, 0, err
			}
			if matches(entry, filter) {
				matched = append(matched, entry)
			}
		}
		// A short page is the last page of the window; anything else is a full
		// page that may still have unread rows behind it.
		if len(rows) < lokiQueryPageSize {
			break
		}
		next, ok := advanceLokiPage(pageWindow, rows, direction)
		if !ok {
			break
		}
		pageWindow = next
	}
	sort.SliceStable(matched, func(i, j int) bool {
		comparison := compareLogEntries(matched[i], matched[j])
		if filter.Ascending {
			return comparison < 0
		}
		return comparison > 0
	})
	total := int64(len(matched))
	if lokiCountableFilter(filter) {
		counted, err := s.count(ctx, window)
		if err != nil {
			return nil, 0, err
		}
		total = counted
	}
	return pageLogs(matched, total, filter.Offset, limit), total, nil
}

// Count implements the optional counter interface used by dashboards. Loki
// only agrees with the local matcher for filters that LogQL can express
// exactly, so richer filters are reported as unsupported and the caller falls
// back to Query.
func (s *LokiSink) Count(ctx context.Context, filter storage.LogFilter) (int64, bool, error) {
	if !lokiCountableFilter(filter) {
		return 0, false, nil
	}
	window, err := s.queryWindow(filter)
	if err != nil {
		return 0, false, err
	}
	total, err := s.count(ctx, window)
	if err != nil {
		return 0, false, err
	}
	return total, true, nil
}

func lokiCountableFilter(filter storage.LogFilter) bool {
	if strings.TrimSpace(filter.Search) != "" || len(filter.Tags) > 0 {
		return false
	}
	// ID matches either id or trace_id locally, which LogQL cannot express as
	// one exact line filter, so such reads fall back to the scanned total.
	if strings.TrimSpace(filter.ID) != "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(filter.Kind)) {
	case "", "all":
	default:
		return false
	}
	return !hasKeysetFilter(filter)
}

type lokiQueryWindow struct {
	selector string
	start    time.Time
	end      time.Time
}

// queryWindow resolves the read range and the LogQL selector. Explicit range
// bounds win; cursor bounds narrow them; a missing range defaults to the last
// lokiDefaultQueryWindow instead of Loki's full retention.
func (s *LokiSink) queryWindow(filter storage.LogFilter) (lokiQueryWindow, error) {
	end := filter.EndTime.UTC()
	if end.IsZero() {
		end = time.Now().UTC()
	}
	start := filter.StartTime.UTC()
	if start.IsZero() {
		start = end.Add(-lokiDefaultQueryWindow)
	}
	if !filter.BeforeTime.IsZero() && filter.BeforeTime.Before(end) {
		end = filter.BeforeTime.UTC()
	}
	if !filter.AfterTime.IsZero() && filter.AfterTime.After(start) {
		start = filter.AfterTime.UTC()
	}
	if !filter.WatermarkTime.IsZero() {
		if filter.Ascending {
			if filter.WatermarkTime.After(start) {
				start = filter.WatermarkTime.UTC()
			}
		} else if filter.WatermarkTime.Before(end) {
			end = filter.WatermarkTime.UTC()
		}
	}
	if !start.Before(end) {
		start = end.Add(-lokiDefaultQueryWindow)
	}
	selector, err := s.logqlSelector(filter)
	if err != nil {
		return lokiQueryWindow{}, err
	}
	return lokiQueryWindow{selector: selector, start: start, end: end}, nil
}

func (s *LokiSink) logqlSelector(filter storage.LogFilter) (string, error) {
	labels := make(map[string]string, len(s.cfg.Labels)+1)
	for key, value := range s.cfg.Labels {
		labels[key] = value
	}
	if _, ok := labels["job"]; !ok {
		labels["job"] = lokiDefaultJobLabel
	}
	if site := strings.TrimSpace(filter.SiteID); site != "" {
		labels["site_id"] = site
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+lokiQuote(labels[key]))
	}
	selector := "{" + strings.Join(parts, ", ") + "}"
	for _, expression := range lokiLineFilters(filter) {
		selector += " " + expression
	}
	return selector, nil
}

// lokiLineFilters narrows the scan with literal JSON field filters. Every row
// is still verified by matches(), so these filters only reduce transfer.
func lokiLineFilters(filter storage.LogFilter) []string {
	filters := make([]string, 0, 6)
	addField := func(field, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		encoded, err := json.Marshal(map[string]string{field: value})
		if err != nil {
			return
		}
		needle := strings.TrimSuffix(strings.TrimPrefix(string(encoded), "{"), "}")
		filters = append(filters, "|~ "+lokiQuote(regexp.QuoteMeta(needle)))
	}
	addField("trace_id", filter.TraceID)
	addField("client_ip", filter.ClientIP)
	addField("category", filter.Category)
	addField("action", filter.Action)
	// Search is matched against decoded field values by matches(), so a LogQL
	// line filter cannot express it: a phrase containing quotes is stored
	// escaped in the JSON line and the raw-line regex would drop a row that the
	// local matcher accepts. Field filters above match JSON literals and are
	// still verified locally, so they stay as a transfer optimisation.
	return filters
}

type lokiQueryResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string            `json:"resultType"`
		Result     []lokiResultEntry `json:"result"`
	} `json:"data"`
}

// lokiResultEntry covers both API shapes: range queries return per-stream
// values, while instant queries (used for counts) return a single value pair.
type lokiResultEntry struct {
	Stream map[string]string `json:"stream"`
	Values []json.RawMessage `json:"values"`
	Value  []json.RawMessage `json:"value"`
}

type lokiValueRow struct {
	timestamp string
	line      string
}

func (s *LokiSink) queryRange(ctx context.Context, window lokiQueryWindow, limit int, direction string) ([]lokiValueRow, error) {
	form := url.Values{}
	form.Set("query", window.selector)
	form.Set("start", strconv.FormatInt(window.start.UnixNano(), 10))
	form.Set("end", strconv.FormatInt(window.end.UnixNano(), 10))
	form.Set("limit", strconv.Itoa(limit))
	form.Set("direction", direction)
	endpoint := s.base + lokiQueryRangePath + "?" + form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	s.applyHeaders(req)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer netguard.DrainAndClose(resp.Body)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, lokiMaxErrorBodyBytes))
		return nil, fmt.Errorf("loki returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out lokiQueryResult
	if err := decodeBoundedLogQueryJSON(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("decode loki query_range: %w", err)
	}
	rows := make([]lokiValueRow, 0, limit)
	for _, stream := range out.Data.Result {
		for _, raw := range stream.Values {
			row, err := decodeLokiValue(raw)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// advanceLokiPage moves the window past the rows just read. Loki returns
// nanosecond timestamps as decimal strings. It reports false when the window
// cannot move — an empty page, no parsable timestamp, or every row sharing one
// timestamp — because continuing would re-read the same rows forever.
func advanceLokiPage(window lokiQueryWindow, rows []lokiValueRow, direction string) (lokiQueryWindow, bool) {
	var boundary int64
	found := false
	for _, row := range rows {
		stamp, err := strconv.ParseInt(strings.TrimSpace(row.timestamp), 10, 64)
		if err != nil {
			continue
		}
		if !found {
			boundary = stamp
			found = true
			continue
		}
		if direction == "forward" {
			if stamp > boundary {
				boundary = stamp
			}
			continue
		}
		if stamp < boundary {
			boundary = stamp
		}
	}
	if !found {
		return lokiQueryWindow{}, false
	}
	next := window
	if direction == "forward" {
		next.start = time.Unix(0, boundary).UTC().Add(time.Nanosecond)
		if next.start.After(window.end) {
			return lokiQueryWindow{}, false
		}
		return next, true
	}
	next.end = time.Unix(0, boundary).UTC().Add(-time.Nanosecond)
	if next.end.Before(window.start) {
		return lokiQueryWindow{}, false
	}
	return next, true
}

func decodeLokiValue(raw json.RawMessage) (lokiValueRow, error) {
	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil {
		return lokiValueRow{}, fmt.Errorf("decode loki value: %w", err)
	}
	if len(pair) < 2 {
		return lokiValueRow{}, fmt.Errorf("decode loki value: expected timestamp and line")
	}
	var stamp, line string
	if err := json.Unmarshal(pair[0], &stamp); err != nil {
		return lokiValueRow{}, fmt.Errorf("decode loki timestamp: %w", err)
	}
	if err := json.Unmarshal(pair[1], &line); err != nil {
		return lokiValueRow{}, fmt.Errorf("decode loki line: %w", err)
	}
	return lokiValueRow{timestamp: stamp, line: line}, nil
}

func lokiDecodeRow(row lokiValueRow) (storage.LogEntry, error) {
	stamp, err := strconv.ParseInt(strings.TrimSpace(row.timestamp), 10, 64)
	if err != nil {
		return storage.LogEntry{}, fmt.Errorf("decode loki timestamp %q: %w", row.timestamp, err)
	}
	when := time.Unix(0, stamp).UTC()
	entry, err := decodeLogEntryJSON([]byte(row.line))
	if err != nil {
		// Rows produced by other Loki clients may not be JSON; keep the raw
		// line as the message so the entry remains searchable and visible.
		return storage.LogEntry{Timestamp: when, Message: row.line}, nil
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = when
	}
	if entry.Message == "" && entry.Payload == "" && entry.URI == "" && entry.ID == "" && entry.TraceID == "" {
		// A JSON line from a foreign schema decodes to an empty entry; fall
		// back to the raw line instead of hiding the content.
		entry.Message = row.line
	}
	return entry, nil
}

// count runs the LogQL equivalent of COUNT(*) for the same selector, keeping
// totals exact for filters the local matcher and LogQL express identically.
func (s *LokiSink) count(ctx context.Context, window lokiQueryWindow) (int64, error) {
	// Preserve the requested range. Falling back to the default window made a
	// sub-second selection report a whole day of logs while query_range still
	// fetched only the narrow range. Milliseconds keep fractional spans exact.
	span := window.end.Sub(window.start)
	if span < time.Millisecond {
		span = time.Millisecond
	}
	query := fmt.Sprintf("sum(count_over_time(%s[%dms]))", window.selector, span.Milliseconds())
	form := url.Values{}
	form.Set("query", query)
	form.Set("time", strconv.FormatInt(window.end.UnixNano(), 10))
	endpoint := s.base + lokiQueryPath + "?" + form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	s.applyHeaders(req)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer netguard.DrainAndClose(resp.Body)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, lokiMaxErrorBodyBytes))
		return 0, fmt.Errorf("loki returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out lokiQueryResult
	if err := decodeBoundedLogQueryJSON(resp.Body, &out); err != nil {
		return 0, fmt.Errorf("decode loki count: %w", err)
	}
	return lokiCountFromResult(out)
}

func lokiCountFromResult(out lokiQueryResult) (int64, error) {
	if out.Status != "" && !strings.EqualFold(out.Status, "success") {
		return 0, fmt.Errorf("loki count returned status %q", out.Status)
	}
	if len(out.Data.Result) == 0 || len(out.Data.Result[0].Value) < 2 {
		return 0, nil
	}
	var text string
	if err := json.Unmarshal(out.Data.Result[0].Value[1], &text); err != nil {
		var number float64
		if err := json.Unmarshal(out.Data.Result[0].Value[1], &number); err != nil {
			return 0, fmt.Errorf("decode loki count value: %w", err)
		}
		return int64(number + 0.5), nil
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	if err != nil {
		return 0, fmt.Errorf("decode loki count value %q: %w", text, err)
	}
	return int64(value + 0.5), nil
}

func lokiQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
