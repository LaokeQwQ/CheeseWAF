package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

func testAlert() monitor.Alert {
	return monitor.Alert{
		RuleID: "rule-1", Name: "Auth burst", Metric: "auth_failures",
		Value: 12, Threshold: 10, Severity: "high",
		Message: "too many failures", StartsAt: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
	}
}

func TestDingTalkSignsAndFormats(t *testing.T) {
	var gotQuery []string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = append(gotQuery, r.URL.Query().Get("timestamp"), r.URL.Query().Get("sign"))
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := config.NotifierConfig{ID: "ding", Type: "dingtalk", Endpoint: server.URL, Token: "secret", MsgType: "markdown"}
	notifier := NewDingTalk(cfg, server.Client())
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
	if len(gotQuery) != 2 || gotQuery[0] == "" || gotQuery[1] == "" {
		t.Fatalf("query = %#v", gotQuery)
	}
	if gotBody["msgtype"] != "markdown" {
		t.Fatalf("body = %#v", gotBody)
	}
}

func TestFeishuSignsAndFormats(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := config.NotifierConfig{ID: "fs", Type: "feishu", Endpoint: server.URL, Token: "secret", MsgType: "text"}
	notifier := NewFeishu(cfg, server.Client())
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
	if gotBody["msg_type"] != "text" || gotBody["timestamp"] == nil || gotBody["sign"] == nil {
		t.Fatalf("body = %#v", gotBody)
	}
}

func TestEmailBuildsSafeMessage(t *testing.T) {
	var captured []byte
	cfg := config.NotifierConfig{
		ID: "mail", Type: "email", SMTPHost: "localhost", SMTPPort: 587,
		From: "waf@example.test", To: "ops@example.test", SubjectPrefix: "[WAF]",
	}
	notifier := NewEmail(cfg, func(_ string, _ smtp.Auth, _ string, _ []string, message []byte) error {
		captured = append([]byte(nil), message...)
		return nil
	})
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
	text := string(captured)
	for _, want := range []string{"From: waf@example.test", "To: ops@example.test", "Subject: [WAF] Auth burst", "MIME-Version: 1.0", "Auth burst"} {
		if !strings.Contains(text, want) {
			t.Fatalf("message missing %q:\n%s", want, text)
		}
	}
}

func TestEmailRejectsHeaderInjection(t *testing.T) {
	cfg := config.NotifierConfig{ID: "mail", Type: "email", SMTPHost: "localhost", From: "waf@example.test", To: "ops@example.test\r\nBcc: evil@example.test"}
	notifier := NewEmail(cfg, func(string, smtp.Auth, string, []string, []byte) error { return nil })
	if err := notifier.Notify(context.Background(), testAlert()); err == nil {
		t.Fatal("expected header injection rejection")
	}
}
