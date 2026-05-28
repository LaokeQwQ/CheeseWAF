package log_sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
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

func (s *ClickHouseSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, fmt.Errorf("clickhouse query is not implemented")
}

func (s *ClickHouseSink) Flush(context.Context) error {
	return nil
}

func (s *ClickHouseSink) Close() error {
	return nil
}
