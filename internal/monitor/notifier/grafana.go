package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// Grafana creates annotations on a Grafana dashboard through the annotations
// API. The API token is stored in config.NotifierConfig.Token and sent as a
// bearer token; it is never placed in the JSON body.
type Grafana struct {
	cfg    config.NotifierConfig
	client *http.Client
	now    func() time.Time
}

func NewGrafana(cfg config.NotifierConfig, client *http.Client) *Grafana {
	if client == nil {
		client = newNotifierHTTPClient(cfg.AllowPrivateEndpoint)
	}
	return &Grafana{cfg: cfg, client: client, now: func() time.Time { return time.Now().UTC() }}
}

func (g *Grafana) Notify(ctx context.Context, alert monitor.Alert) error {
	if g == nil || strings.TrimSpace(g.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := grafanaAnnotationsEndpoint(g.cfg)
	if err != nil {
		return err
	}
	occurredAt := alert.StartsAt
	if occurredAt.IsZero() {
		occurredAt = g.now()
	}
	payload := map[string]any{
		"text": grafanaAnnotationText(alert),
		"tags": grafanaAnnotationTags(alert),
		"time": occurredAt.UTC().UnixMilli(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("grafana notifier %q could not encode annotation: %w", grafanaNotifierName(g.cfg), err)
	}
	headers := make(map[string]string, len(g.cfg.Headers)+1)
	for key, value := range g.cfg.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers[key] = value
	}
	if token := strings.TrimSpace(g.cfg.Token); token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	if err := deliverJSON(ctx, g.client, endpoint, body, headers); err != nil {
		return fmt.Errorf("grafana notifier %q: %w", grafanaNotifierName(g.cfg), err)
	}
	return nil
}

func grafanaAnnotationsEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return "", fmt.Errorf("grafana notifier %q endpoint is invalid: %w", grafanaNotifierName(cfg), err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("grafana notifier %q endpoint must be an absolute URL", grafanaNotifierName(cfg))
	}
	if strings.TrimSpace(cfg.Token) != "" && !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("grafana notifier %q requires an HTTPS endpoint when an API token is configured", grafanaNotifierName(cfg))
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/annotations"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func grafanaNotifierName(cfg config.NotifierConfig) string {
	if id := strings.TrimSpace(cfg.ID); id != "" {
		return id
	}
	return "grafana"
}

// grafanaAnnotationText flattens an alert into the single text field Grafana
// annotations accept, reusing the shared markdown rendering without its
// heading marker.
func grafanaAnnotationText(alert monitor.Alert) string {
	title, body := alertTitleText(alert)
	body = strings.TrimSpace(strings.TrimPrefix(body, "### "+title))
	if body == "" {
		return title
	}
	return title + "\n\n" + body
}

func grafanaAnnotationTags(alert monitor.Alert) []string {
	tags := []string{"cheesewaf"}
	for _, tag := range []struct{ key, value string }{
		{"severity", alert.Severity},
		{"rule", alert.RuleID},
		{"metric", alert.Metric},
	} {
		value := grafanaTagValue(tag.value)
		if value == "" {
			continue
		}
		tags = append(tags, tag.key+":"+value)
	}
	return tags
}

func grafanaTagValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer("\t", "_", "\n", "_", "\r", "_")
	return replacer.Replace(value)
}
