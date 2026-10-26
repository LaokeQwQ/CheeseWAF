package notifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// flashcatNotifier delivers alerts to the Flashduty standard alert event API
// used by Flashcat Cloud. Endpoint is the push base (https://api.flashcat.cloud)
// or a complete dedicated push URL; /event/push/alert/standard is appended when
// the path does not already end with it. Flashduty access control is expressed
// by the integration_key query parameter, which belongs in Endpoint. Token is
// optional and is sent as a bearer token for gateways that authenticate
// CheeseWAF separately; it is never added to the URL or the JSON body.
type flashcatNotifier struct {
	cfg    config.NotifierConfig
	client *http.Client
}

func newFlashcatNotifier(cfg config.NotifierConfig, client *http.Client) *flashcatNotifier {
	return &flashcatNotifier{cfg: cfg, client: notifierHTTPClient(cfg, client)}
}

func (f *flashcatNotifier) Notify(ctx context.Context, alert monitor.Alert) error {
	if f == nil || strings.TrimSpace(f.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := flashcatEventEndpoint(f.cfg)
	if err != nil {
		return fmt.Errorf("notifier %q: %w", f.cfg.ID, err)
	}
	payload := map[string]any{
		"title_rule":   truncateFlashcatField(alertTitle(alert), 512),
		"event_status": flashcatEventStatus(alert.Severity),
		"alert_key":    flashcatEventKey(alert),
		"description":  truncateFlashcatField(alertText(alert), 2048),
		"labels":       flashcatLabels(alert),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notifier %q could not encode event: %w", f.cfg.ID, err)
	}
	return sendJSON(ctx, f.cfg, f.client, jsonDelivery{
		endpoint: endpoint,
		body:     body,
		headers:  notifierHeaders(f.cfg, "Authorization", bearerValue(f.cfg.Token)),
	})
}

func flashcatEventEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint is invalid: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("endpoint must be an absolute URL")
	}
	if parsed.User != nil {
		return "", errors.New("endpoint must not contain credentials")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if strings.TrimSpace(cfg.Token) != "" {
			return "", errors.New("endpoint must use HTTPS when a token is configured")
		}
	default:
		return "", errors.New("endpoint must use HTTP or HTTPS")
	}
	const eventsPath = "/event/push/alert/standard"
	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(strings.ToLower(path), eventsPath) {
		path += eventsPath
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// flashcatEventStatus maps CheeseWAF severities onto the case-sensitive
// Flashduty event_status values.
func flashcatEventStatus(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "fatal", "emergency", "high":
		return "Critical"
	case "info", "low", "notice", "debug":
		return "Info"
	case "ok", "resolved", "recovered", "success":
		return "Ok"
	default:
		return "Warning"
	}
}

// flashcatEventKey returns a stable alert identifier so Flashduty can merge
// repeated notifications and correlate a later recovery.
func flashcatEventKey(alert monitor.Alert) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		alert.RuleID, alert.Name, alert.Metric, alert.StartsAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")))
	return "cheesewaf-" + hex.EncodeToString(sum[:16])
}

func flashcatLabels(alert monitor.Alert) map[string]string {
	labels := map[string]string{"source": "cheesewaf"}
	for key, value := range map[string]string{
		"severity": alert.Severity,
		"rule_id":  alert.RuleID,
		"metric":   alert.Metric,
	} {
		if value = strings.TrimSpace(value); value != "" {
			labels[key] = truncateFlashcatField(value, 2048)
		}
	}
	return labels
}

// truncateFlashcatField enforces the documented Flashduty field limits without
// splitting a UTF-8 rune.
func truncateFlashcatField(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
