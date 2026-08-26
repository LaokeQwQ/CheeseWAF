package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

const (
	webhookMaxAttempts = 3
	webhookRetryDelay  = 25 * time.Millisecond
)

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
	parsed, err := url.Parse(w.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("notifier %q endpoint is invalid: %w", w.cfg.ID, err)
	}
	if webhookHasCredentials(w.cfg) && !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("notifier %q requires an HTTPS endpoint when credentials are configured", w.cfg.ID)
	}
	eventID := webhookEventID(alert)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for key, value := range w.cfg.Headers {
		req.Header.Set(key, value)
	}
	if w.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-ID", eventID)
	req.Header.Set("X-Timestamp", timestamp)
	if w.cfg.Token != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Token))
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		req.Header.Set("X-Signature", "sha256="+fmt.Sprintf("%x", mac.Sum(nil)))
	}
	var lastErr error
	for attempt := 1; attempt <= webhookMaxAttempts; attempt++ {
		if attempt > 1 && req.GetBody != nil {
			if req.Body, err = req.GetBody(); err != nil {
				return fmt.Errorf("notifier %q could not replay request body: %w", w.cfg.ID, err)
			}
		}
		resp, requestErr := w.client.Do(req)
		if requestErr == nil {
			netguard.DrainAndClose(resp.Body)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("notifier %q returned %s", w.cfg.ID, resp.Status)
			if !retryableWebhookStatus(resp.StatusCode) {
				return lastErr
			}
		} else {
			lastErr = requestErr
		}
		if attempt == webhookMaxAttempts {
			break
		}
		if err := waitWebhookRetry(ctx, attempt); err != nil {
			return fmt.Errorf("notifier %q delivery stopped after attempt %d: %w", w.cfg.ID, attempt, err)
		}
	}
	return fmt.Errorf("notifier %q delivery failed after %d attempts: %w", w.cfg.ID, webhookMaxAttempts, lastErr)
}

func webhookHasCredentials(cfg config.NotifierConfig) bool {
	if cfg.Token != "" {
		return true
	}
	for key := range cfg.Headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token":
			return true
		}
	}
	return false
}

func webhookEventID(alert monitor.Alert) string {
	body, _ := json.Marshal(alert)
	sum := sha256.Sum256(body)
	return "alert-" + fmt.Sprintf("%x", sum[:16])
}

func retryableWebhookStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
}

func waitWebhookRetry(ctx context.Context, attempt int) error {
	delay := webhookRetryDelay * time.Duration(1<<(attempt-1))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func webhookURLPolicy(allowPrivate bool) netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "notifier",
		HostPurpose:    "notifier endpoint",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   allowPrivate,
	}
}
