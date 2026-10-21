package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
)

type textProvider struct {
	cfg      config.NotifierConfig
	client   *http.Client
	endpoint func() (string, error)
	payload  func(monitor.Alert) any
}

func (p *textProvider) Notify(ctx context.Context, alert monitor.Alert) error {
	endpoint, err := p.endpoint()
	if err != nil {
		return fmt.Errorf("notifier %q: %w", p.cfg.ID, err)
	}
	body, err := json.Marshal(p.payload(alert))
	if err != nil {
		return fmt.Errorf("notifier %q could not encode payload: %w", p.cfg.ID, err)
	}
	return sendJSON(ctx, p.cfg, p.client, jsonDelivery{
		endpoint: endpoint,
		body:     body,
		headers:  p.cfg.Headers,
	})
}

type textContent struct {
	Content string `json:"content"`
}

type dingTalkPayload struct {
	MsgType string      `json:"msgtype"`
	Text    textContent `json:"text"`
}

type feishuContent struct {
	Text string `json:"text"`
}

type feishuPayload struct {
	MsgType string        `json:"msg_type"`
	Content feishuContent `json:"content"`
}

type weComPayload struct {
	MsgType string      `json:"msgtype"`
	Text    textContent `json:"text"`
}

type telegramPayload struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func newDingTalkNotifier(cfg config.NotifierConfig, client *http.Client) *textProvider {
	return &textProvider{
		cfg:      cfg,
		client:   notifierHTTPClient(cfg, client),
		endpoint: func() (string, error) { return dingTalkEndpoint(cfg) },
		payload: func(alert monitor.Alert) any {
			return dingTalkPayload{MsgType: "text", Text: textContent{Content: alertText(alert)}}
		},
	}
}

func newFeishuNotifier(cfg config.NotifierConfig, client *http.Client) *textProvider {
	return &textProvider{
		cfg:      cfg,
		client:   notifierHTTPClient(cfg, client),
		endpoint: func() (string, error) { return requiredHTTPSEndpoint(cfg.Endpoint) },
		payload: func(alert monitor.Alert) any {
			return feishuPayload{MsgType: "text", Content: feishuContent{Text: alertText(alert)}}
		},
	}
}

func newWeComNotifier(cfg config.NotifierConfig, client *http.Client) *textProvider {
	return &textProvider{
		cfg:      cfg,
		client:   notifierHTTPClient(cfg, client),
		endpoint: func() (string, error) { return requiredHTTPSEndpoint(cfg.Endpoint) },
		payload: func(alert monitor.Alert) any {
			return weComPayload{MsgType: "text", Text: textContent{Content: alertText(alert)}}
		},
	}
}

func newTelegramNotifier(cfg config.NotifierConfig, client *http.Client) *textProvider {
	return &textProvider{
		cfg:      cfg,
		client:   notifierHTTPClient(cfg, client),
		endpoint: func() (string, error) { return telegramEndpoint(cfg) },
		payload: func(alert monitor.Alert) any {
			return telegramPayload{ChatID: cfg.To, Text: alertText(alert)}
		},
	}
}

func notifierHTTPClient(cfg config.NotifierConfig, client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return newNotifierHTTPClient(cfg)
}

func requiredHTTPSEndpoint(raw string) (string, error) {
	parsed, err := parseHTTPEndpoint(raw)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("endpoint must use HTTPS")
	}
	return parsed.String(), nil
}

func requiredHTTPEndpoint(raw string) (string, error) {
	parsed, err := parseHTTPEndpoint(raw)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func parseHTTPEndpoint(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("endpoint is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("endpoint is invalid: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return nil, errors.New("endpoint must use http or https")
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("endpoint must include a host")
	}
	return parsed, nil
}

func dingTalkEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := parseHTTPEndpoint(cfg.Endpoint)
	if err != nil {
		return "", err
	}
	if cfg.Token == "" {
		return parsed.String(), nil
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("endpoint must use HTTPS when a secret is configured")
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(cfg.Token))
	_, _ = mac.Write([]byte(timestamp + "\n" + cfg.Token))
	query := parsed.Query()
	query.Set("timestamp", timestamp)
	query.Set("sign", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func telegramEndpoint(cfg config.NotifierConfig) (string, error) {
	raw := strings.TrimSpace(cfg.Endpoint)
	parsed, err := parseHTTPEndpoint(raw)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(cfg.Token)
	if token != "" && !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("endpoint must use HTTPS when a bot token is configured")
	}
	path := strings.TrimRight(parsed.Path, "/")
	if token != "" && !strings.Contains(raw, token) {
		if strings.HasSuffix(path, "/sendMessage") {
			path = strings.TrimSuffix(path, "/sendMessage") + "/bot" + token + "/sendMessage"
		} else {
			path += "/bot" + token
		}
	}
	if !strings.HasSuffix(path, "/sendMessage") {
		path += "/sendMessage"
	}
	parsed.Path = path
	return parsed.String(), nil
}

func alertText(alert monitor.Alert) string {
	title := firstNonEmpty(strings.TrimSpace(alert.Name), strings.TrimSpace(alert.RuleID), "Security alert")
	lines := []string{title}
	if severity := strings.TrimSpace(alert.Severity); severity != "" {
		lines[0] = "[" + severity + "] " + title
	}
	if message := strings.TrimSpace(alert.Message); message != "" {
		lines = append(lines, message)
	}
	if metric := strings.TrimSpace(alert.Metric); metric != "" {
		lines = append(lines, fmt.Sprintf("%s: %g (threshold %g)", metric, alert.Value, alert.Threshold))
	}
	if !alert.StartsAt.IsZero() {
		lines = append(lines, "started at "+alert.StartsAt.UTC().Format(time.RFC3339))
	}
	return strings.Join(lines, "\n")
}
