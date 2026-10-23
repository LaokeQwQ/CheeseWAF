package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// Datadog publishes alerts as Datadog events through the v1 events API. The
// API key is stored in config.NotifierConfig.Token and sent as DD-API-KEY; it
// is never placed in the JSON body. Application keys can be supplied through
// config.NotifierConfig.Headers.
type Datadog struct {
	cfg    config.NotifierConfig
	client *http.Client
}

func NewDatadog(cfg config.NotifierConfig, client *http.Client) *Datadog {
	if client == nil {
		client = newNotifierHTTPClient(cfg.AllowPrivateEndpoint)
	}
	return &Datadog{cfg: cfg, client: client}
}

func (d *Datadog) Notify(ctx context.Context, alert monitor.Alert) error {
	if d == nil || strings.TrimSpace(d.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := datadogEventsEndpoint(d.cfg)
	if err != nil {
		return err
	}
	title, text := alertTitleText(alert)
	payload := map[string]any{
		"title":            title,
		"text":             text,
		"alert_type":       datadogAlertType(alert.Severity),
		"source_type_name": "cheesewaf",
		"tags":             datadogAlertTags(alert),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("datadog notifier %q could not encode event: %w", datadogNotifierName(d.cfg), err)
	}
	headers := make(map[string]string, len(d.cfg.Headers)+1)
	for key, value := range d.cfg.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers[key] = value
	}
	if apiKey := strings.TrimSpace(d.cfg.Token); apiKey != "" {
		headers["DD-API-KEY"] = apiKey
	}
	if err := deliverJSON(ctx, d.client, endpoint, body, headers); err != nil {
		return fmt.Errorf("datadog notifier %q: %w", datadogNotifierName(d.cfg), err)
	}
	return nil
}

func datadogEventsEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return "", fmt.Errorf("datadog notifier %q endpoint is invalid: %w", datadogNotifierName(cfg), err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("datadog notifier %q endpoint must be an absolute URL", datadogNotifierName(cfg))
	}
	if strings.TrimSpace(cfg.Token) != "" && !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("datadog notifier %q requires an HTTPS endpoint when an API key is configured", datadogNotifierName(cfg))
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v1/events"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func datadogNotifierName(cfg config.NotifierConfig) string {
	if id := strings.TrimSpace(cfg.ID); id != "" {
		return id
	}
	return "datadog"
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
