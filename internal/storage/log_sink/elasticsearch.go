package log_sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type ElasticsearchSink struct {
	cfg    config.ElasticsearchConfig
	client *http.Client
}

func NewElasticsearchSink(cfg config.ElasticsearchConfig, client *http.Client) (*ElasticsearchSink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("elasticsearch endpoint is required")
	}
	if cfg.Index == "" {
		cfg.Index = "cheesewaf-logs"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if client == nil {
		client = guardedLogSinkHTTPClient(cfg.Timeout, "elasticsearch endpoint", cfg.AllowPrivateEndpoint)
	}
	return &ElasticsearchSink{cfg: cfg, client: client}, nil
}

func (s *ElasticsearchSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	doc, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	id := entry.ID
	if id == "" {
		id = entry.TraceID
	}
	method := http.MethodPost
	endpoint := strings.TrimRight(s.cfg.Endpoint, "/") + "/" + url.PathEscape(s.cfg.Index) + "/_doc"
	if id != "" {
		method = http.MethodPut
		endpoint += "/" + url.PathEscape(id)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(doc))
	if err != nil {
		return err
	}
	s.applyAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("elasticsearch returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *ElasticsearchSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	query := elasticsearchQuery(filter)
	data, err := json.Marshal(query)
	if err != nil {
		return nil, 0, err
	}
	endpoint := strings.TrimRight(s.cfg.Endpoint, "/") + "/" + url.PathEscape(s.cfg.Index) + "/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	s.applyAuth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("elasticsearch returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		Hits struct {
			Total any `json:"total"`
			Hits  []struct {
				Source storage.LogEntry `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	entries := make([]storage.LogEntry, 0, len(out.Hits.Hits))
	for _, hit := range out.Hits.Hits {
		entries = append(entries, hit.Source)
	}
	return entries, elasticsearchTotal(out.Hits.Total, int64(len(entries))), nil
}

func (s *ElasticsearchSink) Flush(context.Context) error {
	return nil
}

func (s *ElasticsearchSink) Close() error {
	return nil
}

func (s *ElasticsearchSink) applyAuth(req *http.Request) {
	if s.cfg.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+s.cfg.APIKey)
	} else if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
	for key, value := range s.cfg.Headers {
		req.Header.Set(key, value)
	}
}

func elasticsearchQuery(filter storage.LogFilter) map[string]any {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	var filters []map[string]any
	addTerm := func(field, value string) {
		if value != "" {
			filters = append(filters, map[string]any{"term": map[string]any{field: value}})
		}
	}
	addTerm("site_id.keyword", filter.SiteID)
	addTerm("client_ip.keyword", filter.ClientIP)
	addTerm("category.keyword", filter.Category)
	addTerm("action.keyword", filter.Action)
	addTerm("trace_id.keyword", filter.TraceID)
	for _, tag := range filter.Tags {
		addTerm("tags.keyword", tag)
	}
	if !filter.StartTime.IsZero() || !filter.EndTime.IsZero() {
		bounds := map[string]any{}
		if !filter.StartTime.IsZero() {
			bounds["gte"] = filter.StartTime
		}
		if !filter.EndTime.IsZero() {
			bounds["lte"] = filter.EndTime
		}
		filters = append(filters, map[string]any{"range": map[string]any{"timestamp": bounds}})
	}
	query := map[string]any{"match_all": map[string]any{}}
	if len(filters) > 0 {
		query = map[string]any{"bool": map[string]any{"filter": filters}}
	}
	return map[string]any{
		"from":  offset,
		"size":  limit,
		"query": query,
		"sort":  []map[string]any{{"timestamp": map[string]string{"order": "desc"}}},
	}
}

func elasticsearchTotal(total any, fallback int64) int64 {
	switch value := total.(type) {
	case float64:
		return int64(value)
	case map[string]any:
		if raw, ok := value["value"].(float64); ok {
			return int64(raw)
		}
	}
	return fallback
}
