package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// datadogNotifier publishes alerts as Datadog events through the v1 events
// API. The API key is stored in config.NotifierConfig.Token and sent as
// DD-API-KEY; it is never placed in the JSON body. Application keys can be
// supplied through config.NotifierConfig.Headers.
type datadogNotifier struct {
	cfg    config.NotifierConfig
	client *http.Client
}

func newDatadogNotifier(cfg config.NotifierConfig, client *http.Client) *datadogNotifier {
	return &datadogNotifier{cfg: cfg, client: notifierHTTPClient(cfg, client)}
}

func (d *datadogNotifier) Notify(ctx context.Context, alert monitor.Alert) error {
	if d == nil || strings.TrimSpace(d.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := datadogEventsEndpoint(d.cfg)
	if err != nil {
		return fmt.Errorf("notifier %q: %w", d.cfg.ID, err)
	}
	payload := map[string]any{
		"title":            alertTitle(alert),
		"text":             alertText(alert),
		"alert_type":       datadogAlertType(alert.Severity),
		"source_type_name": "cheesewaf",
		"tags":             datadogAlertTags(alert),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notifier %q could not encode event: %w", d.cfg.ID, err)
	}
	return sendJSON(ctx, d.cfg, d.client, jsonDelivery{
		endpoint: endpoint,
		body:     body,
		headers:  notifierHeaders(d.cfg, "DD-API-KEY", d.cfg.Token),
	})
}

func datadogEventsEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint is invalid: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("endpoint must be an absolute URL")
	}
	if strings.TrimSpace(cfg.Token) != "" && !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("endpoint must use HTTPS when an API key is configured")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v1/events"
	parsed.RawPath = ""
	return parsed.String(), nil
}

// datadogAlertType maps alert severities onto the alert_type values accepted
// by the Datadog events API.
func datadogAlertType(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "fatal", "high", "error":
		return "error"
	case "warning", "warn", "medium":
		return "warning"
	case "success":
		return "success"
	default:
		return "info"
	}
}

func datadogAlertTags(alert monitor.Alert) []string {
	tags := []string{"source:cheesewaf"}
	for _, tag := range []struct{ key, value string }{
		{"severity", alert.Severity},
		{"rule", alert.RuleID},
		{"metric", alert.Metric},
	} {
		value := datadogTagValue(tag.value)
		if value == "" {
			continue
		}
		tags = append(tags, tag.key+":"+value)
	}
	return tags
}

// datadogTagValue keeps tag values within the Datadog tag grammar: no spaces
// or commas, and no empty components.
func datadogTagValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "_", ",", "_", "\t", "_", "\n", "_", "\r", "_")
	return replacer.Replace(value)
}
