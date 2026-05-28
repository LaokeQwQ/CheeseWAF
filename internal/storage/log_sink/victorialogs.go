package log_sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	data, err := json.Marshal(entry)
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

func (s *VictoriaLogsSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, fmt.Errorf("victorialogs query is not implemented")
}

func (s *VictoriaLogsSink) Flush(context.Context) error {
	return nil
}

func (s *VictoriaLogsSink) Close() error {
	return nil
}
