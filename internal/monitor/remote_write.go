package monitor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type RemoteWriter struct {
	cfg    config.RemoteWriteConfig
	client *http.Client
}

func NewRemoteWriter(cfg config.RemoteWriteConfig, client *http.Client) *RemoteWriter {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &RemoteWriter{cfg: cfg, client: client}
}

func (w *RemoteWriter) Push(ctx context.Context, snapshot Snapshot) error {
	if w == nil || !w.cfg.Enabled {
		return nil
	}
	if w.cfg.Endpoint == "" {
		return fmt.Errorf("remote_write endpoint is required")
	}
	body := RenderPrometheus(snapshot)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remote_write returned %s", resp.Status)
	}
	return nil
}
