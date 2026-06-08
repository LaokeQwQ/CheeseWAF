package log_sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type VictoriaLogsSink struct {
	cfg    config.VictoriaLogsConfig
	client *http.Client
}

func NewVictoriaLogsSink(cfg config.VictoriaLogsConfig, client *http.Client) (*VictoriaLogsSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("victorialogs endpoint is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &VictoriaLogsSink{cfg: cfg, client: client}, nil
}

func (s *VictoriaLogsSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	row, err := encodeLogEntryForVictoriaLogs(entry)
	if err != nil {
		return err
	}
	data, err := json.Marshal(row)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(append(data, '\n')))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("victorialogs returned %s", resp.Status)
	}
	return nil
}

func (s *VictoriaLogsSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	query := victoriaLogsQuery(filter)
	countBody, err := s.doQuery(ctx, query+" | stats count() total", 1, 0, filter)
	if err != nil {
		return nil, 0, err
	}
	total, err := parseCountJSONLine(countBody, "total")
	if err != nil {
		return nil, 0, fmt.Errorf("decode victorialogs count: %w", err)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	itemBody, err := s.doQuery(ctx, query, limit, offset, filter)
	if err != nil {
		return nil, 0, err
	}
	entries, err := decodeLogEntryJSONLines(itemBody)
	if err != nil {
		return nil, 0, fmt.Errorf("decode victorialogs rows: %w", err)
	}
	return entries, total, nil
}

func (s *VictoriaLogsSink) Flush(context.Context) error {
	return nil
}

func (s *VictoriaLogsSink) Close() error {
	return nil
}

func (s *VictoriaLogsSink) doQuery(ctx context.Context, query string, limit, offset int, filter storage.LogFilter) (io.ReadCloser, error) {
	endpoint, err := victoriaLogsQueryEndpoint(s.cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("query", query)
	if limit > 0 {
		form.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		form.Set("offset", strconv.Itoa(offset))
	}
	if !filter.StartTime.IsZero() {
		form.Set("start", filter.StartTime.UTC().Format(time.RFC3339Nano))
	}
	if !filter.EndTime.IsZero() {
		form.Set("end", filter.EndTime.UTC().Format(time.RFC3339Nano))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("victorialogs returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

func victoriaLogsQueryEndpoint(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(parsed.Path, "/")
	if path == "" || path == "/" || strings.Contains(path, "/insert/") {
		parsed.Path = "/select/logsql/query"
	}
	return parsed.String(), nil
}

func victoriaLogsQuery(filter storage.LogFilter) string {
	var parts []string
	add := func(field, value string) {
		if value != "" {
			parts = append(parts, field+":="+victoriaLogsQuote(value))
		}
	}
	add("site_id", filter.SiteID)
	add("client_ip", filter.ClientIP)
	add("category", filter.Category)
	add("action", filter.Action)
	add("trace_id", filter.TraceID)
	for _, tag := range filter.Tags {
		if tag != "" {
			parts = append(parts, "tags:="+victoriaLogsQuote(tag))
		}
	}
	if len(parts) == 0 {
		return "*"
	}
	return strings.Join(parts, " AND ")
}

func victoriaLogsQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
