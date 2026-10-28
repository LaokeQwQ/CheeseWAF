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
		client = newNotifierHTTPClient(cfg)
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
	headers := make(map[string]string, len(w.cfg.Headers)+5)
	for key, value := range w.cfg.Headers {
		headers[key] = value
	}
	if w.cfg.Token != "" {
		headers["Authorization"] = "Bearer " + w.cfg.Token
	}
	headers["X-Event-ID"] = eventID
	headers["X-Timestamp"] = timestamp
	if w.cfg.Token != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Token))
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		headers["X-Signature"] = "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
	}
	return sendJSON(ctx, w.cfg, w.client, jsonDelivery{
		endpoint: w.cfg.Endpoint,
		body:     body,
		headers:  headers,
	})
}

type jsonDelivery struct {
	endpoint string
	body     []byte
	headers  map[string]string
}

func sendJSON(ctx context.Context, cfg config.NotifierConfig, client *http.Client, delivery jsonDelivery) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, delivery.endpoint, bytes.NewReader(delivery.body))
	if err != nil {
		return err
	}
	for key, value := range delivery.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	var lastErr error
	for attempt := 1; attempt <= webhookMaxAttempts; attempt++ {
		if attempt > 1 && req.GetBody != nil {
			if req.Body, err = req.GetBody(); err != nil {
				return fmt.Errorf("notifier %q could not replay request body: %w", cfg.ID, err)
			}
		}
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			netguard.DrainAndClose(resp.Body)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("notifier %q returned %s", cfg.ID, resp.Status)
			if !retryableWebhookStatus(resp.StatusCode) {
				return lastErr
			}
		} else {
			lastErr = sanitizeDeliveryError(requestErr)
		}
		if attempt == webhookMaxAttempts {
			break
		}
		if err := waitWebhookRetry(ctx, attempt); err != nil {
			return fmt.Errorf("notifier %q delivery stopped after attempt %d: %w", cfg.ID, attempt, err)
		}
	}
	return fmt.Errorf("notifier %q delivery failed after %d attempts: %w", cfg.ID, webhookMaxAttempts, lastErr)
}

func sanitizeDeliveryError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func newNotifierHTTPClient(cfg config.NotifierConfig) *http.Client {
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: 10 * time.Second,
		Policy:  webhookURLPolicy(cfg.AllowPrivateEndpoint),
	})
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
