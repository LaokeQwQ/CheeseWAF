package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// DingTalk delivers alerts to a custom robot webhook. The signing secret is
// stored in config.NotifierConfig.Token; it is never placed in the JSON body.
type DingTalk struct {
	cfg    config.NotifierConfig
	client *http.Client
	now    func() time.Time
}

func NewDingTalk(cfg config.NotifierConfig, client *http.Client) *DingTalk {
	if client == nil {
		client = newNotifierHTTPClient(cfg.AllowPrivateEndpoint)
	}
	return &DingTalk{cfg: cfg, client: client, now: func() time.Time { return time.Now().UTC() }}
}

func (d *DingTalk) Notify(ctx context.Context, alert monitor.Alert) error {
	if d == nil || strings.TrimSpace(d.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := d.signedEndpoint()
	if err != nil {
		return err
	}
	msgType := strings.ToLower(strings.TrimSpace(d.cfg.MsgType))
	if msgType == "" {
		msgType = "markdown"
	}
	title, text := alertTitleText(alert)
	var payload map[string]any
	switch msgType {
	case "text":
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	default:
		payload = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": title, "text": text}}
	}
	payload["at"] = map[string]any{"atMobiles": append([]string(nil), d.cfg.AtMobiles...), "isAtAll": false}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return deliverJSON(ctx, d.client, endpoint, body, nil)
}

func (d *DingTalk) signedEndpoint() (string, error) {
	parsed, err := url.Parse(d.cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("dingtalk endpoint is invalid: %w", err)
	}
	if strings.TrimSpace(d.cfg.Token) == "" {
		return parsed.String(), nil
	}
	timestamp := strconv.FormatInt(d.now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(timestamp+"\n"+d.cfg.Token))
	_, _ = mac.Write(nil)
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	query := parsed.Query()
	query.Set("timestamp", timestamp)
	query.Set("sign", sign)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func alertTitleText(alert monitor.Alert) (string, string) {
	title := strings.TrimSpace(alert.Name)
	if title == "" {
		title = strings.TrimSpace(alert.RuleID)
	}
	if title == "" {
		title = "CheeseWAF alert"
	}
	text := fmt.Sprintf("### %s\n\n- severity: %s\n- rule: %s\n- metric: %s = %.4g (threshold %.4g)\n- message: %s\n- starts_at: %s",
		title, alert.Severity, alert.RuleID, alert.Metric, alert.Value, alert.Threshold, alert.Message, alert.StartsAt.UTC().Format(time.RFC3339))
	return title, text
}
