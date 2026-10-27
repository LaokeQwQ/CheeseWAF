package notifier

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

func testAlert() monitor.Alert {
	return monitor.Alert{
		RuleID:   "php2shell-upload",
		Name:     "PHP upload blocked",
		Metric:   "cheesewaf_php2shell_blocks",
		Value:    12,
		Severity: "critical",
		Message:  "multipart upload blocked",
		StartsAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestDingTalkPayloadAndSignature(t *testing.T) {
	const secret = "dingtalk-secret"
	var received dingTalkPayload
	var timestamp, sign, accessToken string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode DingTalk payload: %v", err)
		}
		query := r.URL.Query()
		timestamp = query.Get("timestamp")
		sign = query.Get("sign")
		accessToken = query.Get("access_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "dingtalk",
		Type:     "dingtalk",
		Endpoint: server.URL + "/robot/send?access_token=token-value",
		Token:    secret,
		Enabled:  true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create DingTalk provider: %v", err)
	}
	alert := testAlert()
	if err := provider.Notify(context.Background(), alert); err != nil {
		t.Fatalf("deliver DingTalk alert: %v", err)
	}
	if received.MsgType != "text" || received.Text.Content != alertText(alert) {
		t.Fatalf("unexpected DingTalk payload: %+v", received)
	}
	if accessToken != "token-value" {
		t.Fatalf("endpoint query parameters were not preserved: %q", accessToken)
	}
	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
		t.Fatalf("invalid DingTalk timestamp %q: %v", timestamp, err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "\n" + secret))
	wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if sign != wantSign {
		t.Fatalf("unexpected DingTalk signature: got %q want %q", sign, wantSign)
	}
}

func TestDingTalkRejectsHTTPWhenSecretConfigured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("credentialed DingTalk notifier must not dial an HTTP endpoint")
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "dingtalk",
		Type:     "dingtalk",
		Endpoint: server.URL,
		Token:    "secret",
		Enabled:  true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create DingTalk provider: %v", err)
	}
	err = provider.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS guard error, got %v", err)
	}
}

func TestFeishuPayload(t *testing.T) {
	var received feishuPayload
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode Feishu payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "feishu",
		Type:     "feishu",
		Endpoint: server.URL + "/open-apis/bot/v2/hook/abc",
		Enabled:  true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create Feishu provider: %v", err)
	}
	alert := testAlert()
	if err := provider.Notify(context.Background(), alert); err != nil {
		t.Fatalf("deliver Feishu alert: %v", err)
	}
	if received.MsgType != "text" || received.Content.Text != alertText(alert) {
		t.Fatalf("unexpected Feishu payload: %+v", received)
	}
}

func TestWeComPayload(t *testing.T) {
	var received weComPayload
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode WeCom payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "wecom",
		Type:     "wecom",
		Endpoint: server.URL + "/cgi-bin/webhook/send?key=abc",
		Enabled:  true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create WeCom provider: %v", err)
	}
	alert := testAlert()
	if err := provider.Notify(context.Background(), alert); err != nil {
		t.Fatalf("deliver WeCom alert: %v", err)
	}
	if received.MsgType != "text" || received.Text.Content != alertText(alert) {
		t.Fatalf("unexpected WeCom payload: %+v", received)
	}
}

func TestTelegramPayload(t *testing.T) {
	const token = "123456:bot-token"
	var received telegramPayload
	var path string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode Telegram payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "telegram",
		Type:     "telegram",
		Endpoint: server.URL,
		To:       "-100200300",
		Token:    token,
		Enabled:  true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create Telegram provider: %v", err)
	}
	alert := testAlert()
	if err := provider.Notify(context.Background(), alert); err != nil {
		t.Fatalf("deliver Telegram alert: %v", err)
	}
	if path != "/bot"+token+"/sendMessage" {
		t.Fatalf("unexpected Telegram path %q", path)
	}
	if received.ChatID != "-100200300" || received.Text != alertText(alert) {
		t.Fatalf("unexpected Telegram payload: %+v", received)
	}
}

func TestTelegramDoesNotDuplicateEndpointToken(t *testing.T) {
	const token = "123456:bot-token"
	var path string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "telegram",
		Type:     "telegram",
		Endpoint: server.URL + "/bot" + token,
		To:       "42",
		Token:    token,
		Enabled:  true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create Telegram provider: %v", err)
	}
	if err := provider.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("deliver Telegram alert: %v", err)
	}
	if path != "/bot"+token+"/sendMessage" {
		t.Fatalf("unexpected Telegram path %q", path)
	}
}

func TestWebhookProviderPayloadUnchanged(t *testing.T) {
	var received struct {
		Type     string        `json:"type"`
		Target   string        `json:"target"`
		Alert    monitor.Alert `json:"alert"`
		Severity string        `json:"severity"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("unexpected content type %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:                   "webhook",
		Type:                 "webhook",
		Endpoint:             server.URL,
		To:                   "ops",
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}, server.Client())
	if err != nil {
		t.Fatalf("create webhook provider: %v", err)
	}
	alert := testAlert()
	if err := provider.Notify(context.Background(), alert); err != nil {
		t.Fatalf("deliver webhook alert: %v", err)
	}
	if received.Type != "webhook" || received.Target != "ops" || received.Severity != alert.Severity || received.Alert.RuleID != alert.RuleID {
		t.Fatalf("unexpected webhook payload: %+v", received)
	}
}

func TestManagerRejectsUnknownProviderType(t *testing.T) {
	manager := NewManager([]config.NotifierConfig{{
		ID:      "pager",
		Type:    "pagerduty",
		Enabled: true,
	}})
	err := manager.Notify(context.Background(), []monitor.Alert{{RuleID: "unknown-provider"}})
	if err == nil {
		t.Fatal("expected unknown provider type error")
	}
	if !strings.Contains(err.Error(), `notifier "pager" has unsupported type "pagerduty"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmailRequiresExplicitConfiguration(t *testing.T) {
	provider, err := NewRegistry().New(config.NotifierConfig{ID: "email", Type: "email", Enabled: true}, nil)
	if err != nil {
		t.Fatalf("create email provider: %v", err)
	}
	err = provider.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Fatalf("expected missing endpoint error, got %v", err)
	}

	provider, err = NewRegistry().New(config.NotifierConfig{
		ID:       "email",
		Type:     "email",
		Endpoint: "smtp://127.0.0.1:2525",
		Headers:  map[string]string{"from": "waf@example.test"},
		Enabled:  true,
	}, nil)
	if err != nil {
		t.Fatalf("create email provider: %v", err)
	}
	err = provider.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "valid recipient") {
		t.Fatalf("expected missing recipient error, got %v", err)
	}

	provider, err = NewRegistry().New(config.NotifierConfig{
		ID:       "email",
		Type:     "email",
		Endpoint: "smtp://127.0.0.1:2525",
		To:       "security@example.test",
		Enabled:  true,
	}, nil)
	if err != nil {
		t.Fatalf("create email provider: %v", err)
	}
	err = provider.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "headers.from") {
		t.Fatalf("expected missing sender error, got %v", err)
	}
}

func TestSMTPEndpointParsing(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		address string
		host    string
		wantErr bool
	}{
		{name: "smtp scheme", raw: "smtp://mail.example.test:587", address: "mail.example.test:587", host: "mail.example.test"},
		{name: "host port", raw: "mail.example.test:25", address: "mail.example.test:25", host: "mail.example.test"},
		{name: "ipv6", raw: "smtp://[::1]:2525", address: "[::1]:2525", host: "::1"},
		{name: "missing endpoint", raw: "", wantErr: true},
		{name: "missing port", raw: "mail.example.test", wantErr: true},
		{name: "unsupported scheme", raw: "https://mail.example.test:587", wantErr: true},
		{name: "credentials", raw: "smtp://user:pass@mail.example.test:587", wantErr: true},
		{name: "path", raw: "smtp://mail.example.test:587/path", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, host, err := smtpEndpoint(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got address %q host %q", address, host)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if address != test.address || host != test.host {
				t.Fatalf("got address %q host %q, want %q/%q", address, host, test.address, test.host)
			}
		})
	}
}

func TestEmailDeliversOverSMTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake SMTP server: %v", err)
	}
	messages := make(chan string, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		writeLine := func(line string) bool {
			if _, err := writer.WriteString(line + "\r\n"); err != nil {
				return false
			}
			return writer.Flush() == nil
		}
		if !writeLine("220 localhost ESMTP") {
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
				if !writeLine("250 localhost") {
					return
				}
			case strings.HasPrefix(command, "MAIL FROM"), strings.HasPrefix(command, "RCPT TO"):
				if !writeLine("250 OK") {
					return
				}
			case command == "DATA":
				if !writeLine("354 End data with <CR><LF>.<CR><LF>") {
					return
				}
				var message strings.Builder
				for {
					dataLine, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if dataLine == ".\r\n" {
						break
					}
					message.WriteString(dataLine)
				}
				messages <- message.String()
				if !writeLine("250 OK") {
					return
				}
			case command == "QUIT":
				_ = writeLine("221 Bye")
				return
			default:
				if !writeLine("250 OK") {
					return
				}
			}
		}
	}()
	defer func() {
		_ = listener.Close()
		<-serverDone
	}()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "email",
		Type:     "email",
		Endpoint: listener.Addr().String(),
		To:       "security@example.test",
		Token:    "unused-password",
		Headers:  map[string]string{"from": "CheeseWAF <waf@example.test>"},
		Enabled:  true,
		// The fake SMTP server is bound to loopback, which the notifier
		// rejects unless the operator opted in.
		AllowPrivateEndpoint: true,
	}, nil)
	if err != nil {
		t.Fatalf("create email provider: %v", err)
	}
	alert := testAlert()
	if err := provider.Notify(context.Background(), alert); err != nil {
		t.Fatalf("deliver email alert: %v", err)
	}
	select {
	case message := <-messages:
		for _, want := range []string{
			`From: "CheeseWAF" <waf@example.test>`,
			"To: <security@example.test>",
			"Subject: [critical] PHP upload blocked",
			strings.ReplaceAll(alertText(alert), "\n", "\r\n"),
		} {
			if !strings.Contains(message, want) {
				t.Fatalf("SMTP message missing %q:\n%s", want, message)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("fake SMTP server did not receive a message")
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: errors.New("network down")}
}

func TestNotifierErrorDoesNotLeakEndpointSecret(t *testing.T) {
	cfg := config.NotifierConfig{
		ID: "telegram", Type: "telegram", Enabled: true,
		Endpoint: "https://api.telegram.org", Token: "SECRET-TOKEN", To: "123",
	}
	notifier := NewWebhook(cfg, &http.Client{Transport: failingTransport{}})
	err := notifier.Notify(context.Background(), monitor.Alert{RuleID: "r"})
	if err == nil {
		t.Fatal("expected delivery error")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("error leaked secret: %v", err)
	}
}

func TestFeishuRequiresHTTPS(t *testing.T) {
	cfg := config.NotifierConfig{ID: "feishu", Type: "feishu", Endpoint: "http://open.feishu.cn/hook"}
	if _, err := NewRegistry().New(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if err := notifierMustNotify(t, cfg); err == nil {
		t.Fatal("expected HTTPS rejection")
	}
}

func notifierMustNotify(t *testing.T, cfg config.NotifierConfig) error {
	t.Helper()
	p, err := NewRegistry().New(cfg, nil)
	if err != nil {
		return err
	}
	return p.Notify(context.Background(), monitor.Alert{RuleID: "r"})
}
