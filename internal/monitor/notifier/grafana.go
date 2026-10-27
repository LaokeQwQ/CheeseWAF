package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// grafanaNotifier creates annotations on a Grafana dashboard through the
// annotations API. The API token is stored in config.NotifierConfig.Token and
// sent as a bearer token; it is never placed in the JSON body.
type grafanaNotifier struct {
	cfg    config.NotifierConfig
	client *http.Client
	now    func() time.Time
}

func newGrafanaNotifier(cfg config.NotifierConfig, client *http.Client) *grafanaNotifier {
	return &grafanaNotifier{
		cfg:    cfg,
		client: notifierHTTPClient(cfg, client),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func (g *grafanaNotifier) Notify(ctx context.Context, alert monitor.Alert) error {
	if g == nil || strings.TrimSpace(g.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := grafanaAnnotationsEndpoint(g.cfg)
	if err != nil {
		return fmt.Errorf("notifier %q: %w", g.cfg.ID, err)
	}
	occurredAt := alert.StartsAt
	if occurredAt.IsZero() {
		occurredAt = g.now()
	}
	payload := map[string]any{
		"text": alertText(alert),
		"tags": grafanaAnnotationTags(alert),
		"time": occurredAt.UTC().UnixMilli(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notifier %q could not encode annotation: %w", g.cfg.ID, err)
	}
	return sendJSON(ctx, g.cfg, g.client, jsonDelivery{
		endpoint: endpoint,
		body:     body,
		headers:  notifierHeaders(g.cfg, "Authorization", bearerValue(g.cfg.Token)),
	})
}

func grafanaAnnotationsEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint is invalid: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("endpoint must be an absolute URL")
	}
	if strings.TrimSpace(cfg.Token) != "" && !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("endpoint must use HTTPS when an API token is configured")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/annotations"
	parsed.RawPath = ""
	return parsed.String(), nil
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
