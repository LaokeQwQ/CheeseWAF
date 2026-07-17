package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

type Notifier interface {
	Notify(ctx context.Context, alert monitor.Alert) error
}

type Manager struct {
	notifiers []Notifier
}

func NewManager(configs []config.NotifierConfig) *Manager {
	manager := &Manager{}
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		manager.notifiers = append(manager.notifiers, NewWebhook(cfg, nil))
	}
	return manager
}

func (m *Manager) Notify(ctx context.Context, alerts []monitor.Alert) error {
	if m == nil || len(alerts) == 0 {
		return nil
	}
	var deliveryErrors []error
	for _, alert := range alerts {
		for _, notifier := range m.notifiers {
			if err := notifier.Notify(ctx, alert); err != nil {
				deliveryErrors = append(deliveryErrors, err)
			}
		}
	}
	return errors.Join(deliveryErrors...)
}

func errorsJoin(values []error) error {
	return errors.Join(values...)
}

type Webhook struct {
	cfg    config.NotifierConfig
	client *http.Client
}

func NewWebhook(cfg config.NotifierConfig, client *http.Client) *Webhook {
	if client == nil {
		client = netguard.NewHTTPClient(netguard.HTTPClientOptions{
			Timeout: 10 * time.Second,
			Policy:  webhookURLPolicy(cfg.AllowPrivateEndpoint),
		})
	}
	return &Webhook{cfg: cfg, client: client}
}

func (w *Webhook) Notify(ctx context.Context, alert monitor.Alert) error {
	if w == nil || w.cfg.Endpoint == "" {
		return nil
	}
	payload := map[string]any{
		"type":     w.cfg.Type,
		"target":   w.cfg.To,
		"alert":    alert,
		"severity": alert.Severity,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range w.cfg.Headers {
		req.Header.Set(key, value)
	}
	if w.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notifier %q returned %s", w.cfg.ID, resp.Status)
	}
	return nil
}

func webhookURLPolicy(allowPrivate bool) netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "notifier",
		HostPurpose:    "notifier endpoint",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	}
}
