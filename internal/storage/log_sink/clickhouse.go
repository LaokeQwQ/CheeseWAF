package log_sink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type ClickHouseSink struct {
	cfg    config.ClickHouseConfig
	client *http.Client
}

func NewClickHouseSink(cfg config.ClickHouseConfig, client *http.Client) (*ClickHouseSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("clickhouse endpoint is required")
	}
	if cfg.Table == "" {
		cfg.Table = "cheesewaf_logs"
	}
	if cfg.Database == "" {
		cfg.Database = "default"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if _, err := quoteClickHouseIdentifierPath(cfg.Table); err != nil {
		return nil, err
	}
	if client == nil {
		client = guardedLogSinkHTTPClient(cfg.Timeout, "clickhouse endpoint", cfg.AllowPrivateEndpoint)
	}
	return &ClickHouseSink{cfg: cfg, client: client}, nil
}

func (s *ClickHouseSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(s.cfg.Endpoint)
	if err != nil {
		return err
	}
	query := endpoint.Query()
	query.Set("database", s.cfg.Database)
	query.Set("query", fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", s.cfg.Table))
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(append(data, '\n')))
	if err != nil {
		return err
	}
	if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("clickhouse returned %s", resp.Status)
	}
	return nil
}

func (s *ClickHouseSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	table, err := quoteClickHouseIdentifierPath(s.cfg.Table)
	if err != nil {
		return nil, 0, err
	}
	where := clickHouseWhere(filter)
	countBody, err := s.doQuery(ctx, fmt.Sprintf("SELECT count() AS total FROM %s%s FORMAT JSONEachRow", table, where))
	if err != nil {
		return nil, 0, err
	}
	total, err := parseCountJSONLine(countBody, "total")
	if err != nil {
		return nil, 0, fmt.Errorf("decode clickhouse count: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	itemBody, err := s.doQuery(ctx, fmt.Sprintf("SELECT * FROM %s%s ORDER BY timestamp DESC LIMIT %d OFFSET %d FORMAT JSONEachRow", table, where, limit, offset))
	if err != nil {
		return nil, 0, err
	}
	entries, err := decodeLogEntryJSONLines(itemBody)
	if err != nil {
		return nil, 0, fmt.Errorf("decode clickhouse rows: %w", err)
	}
	return entries, total, nil
}

func (s *ClickHouseSink) Flush(context.Context) error {
	return nil
}

func (s *ClickHouseSink) Close() error {
	return nil
}

func (s *ClickHouseSink) doQuery(ctx context.Context, statement string) (io.ReadCloser, error) {
	endpoint, err := url.Parse(s.cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("database", s.cfg.Database)
	query.Set("query", statement)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("clickhouse returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

func clickHouseWhere(filter storage.LogFilter) string {
	var clauses []string
	add := func(field, value string) {
		if value != "" {
			clauses = append(clauses, fmt.Sprintf("%s = %s", field, clickHouseStringLiteral(value)))
		}
	}
	add("site_id", filter.SiteID)
	add("client_ip", filter.ClientIP)
	add("category", filter.Category)
	add("action", filter.Action)
	add("trace_id", filter.TraceID)
	if !filter.StartTime.IsZero() {
		clauses = append(clauses, fmt.Sprintf("timestamp >= parseDateTimeBestEffort(%s)", clickHouseStringLiteral(filter.StartTime.UTC().Format(time.RFC3339Nano))))
	}
	if !filter.EndTime.IsZero() {
		clauses = append(clauses, fmt.Sprintf("timestamp <= parseDateTimeBestEffort(%s)", clickHouseStringLiteral(filter.EndTime.UTC().Format(time.RFC3339Nano))))
	}
	for _, tag := range filter.Tags {
		if tag != "" {
			clauses = append(clauses, fmt.Sprintf("has(tags, %s)", clickHouseStringLiteral(tag)))
		}
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

func clickHouseStringLiteral(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func quoteClickHouseIdentifierPath(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("clickhouse table is required")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("clickhouse table supports table or database.table")
	}
	ident := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	for idx, part := range parts {
		if !ident.MatchString(part) {
			return "", fmt.Errorf("unsafe clickhouse identifier %q", part)
		}
		parts[idx] = "`" + strings.ReplaceAll(part, "`", "``") + "`"
	}
	return strings.Join(parts, "."), nil
}

func parseCountJSONLine(body io.ReadCloser, field string) (int64, error) {
	defer body.Close()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return 0, err
		}
		return numericValue(row[field]), nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}
