package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// Feishu delivers alerts to a Feishu custom bot webhook. The optional signing
// secret is stored in config.NotifierConfig.Token and sent as timestamp/sign
// in the JSON body, as required by Feishu.
type Feishu struct {
	cfg    config.NotifierConfig
	client *http.Client
	now    func() time.Time
}

func NewFeishu(cfg config.NotifierConfig, client *http.Client) *Feishu {
	if client == nil {
		client = newNotifierHTTPClient(cfg.AllowPrivateEndpoint)
	}
	return &Feishu{cfg: cfg, client: client, now: func() time.Time { return time.Now().UTC() }}
}

func (f *Feishu) Notify(ctx context.Context, alert monitor.Alert) error {
	if f == nil || strings.TrimSpace(f.cfg.Endpoint) == "" {
		return nil
	}
	title, text := alertTitleText(alert)
	msgType := strings.ToLower(strings.TrimSpace(f.cfg.MsgType))
	payload := map[string]any{}
	if msgType == "interactive" {
		payload["msg_type"] = "interactive"
		payload["card"] = map[string]any{
			"header": map[string]any{"title": map[string]string{"tag": "plain_text", "content": title}},
			"elements": []any{
				map[string]any{"tag": "div", "text": map[string]string{"tag": "lark_md", "content": text}},
			},
		}
	} else {
		payload["msg_type"] = "text"
		payload["content"] = map[string]string{"text": text}
	}
	if strings.TrimSpace(f.cfg.Token) != "" {
		timestamp := strconv.FormatInt(f.now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(timestamp+"\n"+f.cfg.Token))
		_, _ = mac.Write(nil)
		payload["timestamp"] = timestamp
		payload["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return deliverJSON(ctx, f.client, f.cfg.Endpoint, body, nil)
}
