package notifierpack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

const staticPackJSON = `{
  "api_version": "crp.cheesewaf.io/notifier/v1",
  "provider_id": "static.alert-bridge",
  "type": "staticbridge",
  "version": "0.1.0",
  "namespace": "com.cheesewaf.official",
  "source": "cheesewaf-registry",
  "source_root": "packs/notifiers",
  "config_schema": {
    "dialect": "cheesewaf-notifier-config/v1",
    "fields": []
  },
  "secret_fields": ["token_ref"],
  "endpoint_templates": [
    {
      "name": "notify",
      "url_template": "https://static.example.com/hook",
      "method": "POST",
      "egress_owner": "cheesewaf-core",
      "variables": []
    }
  ],
  "capabilities": ["alert_delivery"]
}`

func testAlert() monitor.Alert {
	return monitor.Alert{
		RuleID:    "php2shell-upload",
		Name:      "PHP upload blocked",
		Metric:    "cheesewaf_php2shell_blocks",
		Value:     7,
		Threshold: 1,
		Severity:  "critical",
		Message:   "multipart upload blocked",
		StartsAt:  time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	}
}

func packForServer(t *testing.T, server *httptest.Server) Pack {
	t.Helper()
	document := strings.Replace(validPackJSON, "https://open.larksuite.com", server.URL, 1)
	pack, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("parse pack for test server: %v", err)
	}
	return pack
}

func TestDelivererNotifyPostsAlert(t *testing.T) {
	type request struct {
		method      string
		path        string
		rawQuery    string
		fullURL     string
		authorized  string
		source      string
		contentType string
		body        map[string]any
	}
	captured := make(chan request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		captured <- request{
			method:      r.Method,
			path:        r.URL.Path,
			rawQuery:    r.URL.RawQuery,
			fullURL:     r.URL.String(),
			authorized:  r.Header.Get("Authorization"),
			source:      r.Header.Get("X-Request-Source"),
			contentType: r.Header.Get("Content-Type"),
			body:        decoded,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pack := packForServer(t, server)
	cfg := config.NotifierConfig{
		ID:                   "lark",
		Type:                 "lark",
		To:                   "abc123",
		Token:                "pack-token",
		Headers:              map[string]string{"X-Request-Source": "cheesewaf"},
		AllowPrivateEndpoint: true,
	}
	deliverer, err := pack.New(cfg, server.Client())
	if err != nil {
		t.Fatalf("build deliverer: %v", err)
	}
	if !strings.HasPrefix(deliverer.endpoint, server.URL) {
		t.Fatalf("endpoint = %q, want host pinned to %q", deliverer.endpoint, server.URL)
	}
	rendered, err := url.Parse(deliverer.endpoint)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	if rendered.Host != serverURL.Host {
		t.Fatalf("endpoint host = %q, want template host %q", rendered.Host, serverURL.Host)
	}
	if err := deliverer.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("notify: %v", err)
	}
	got := <-captured
	if got.method != http.MethodPost {
		t.Fatalf("method = %q", got.method)
	}
	if got.path != "/open-apis/bot/v2/hook/abc123" {
		t.Fatalf("path = %q", got.path)
	}
	if got.rawQuery != "" || strings.Contains(got.fullURL, "pack-token") {
		t.Fatalf("token leaked into URL %q", got.fullURL)
	}
	if got.authorized != "Bearer pack-token" {
		t.Fatalf("authorization = %q", got.authorized)
	}
	if got.source != "cheesewaf" {
		t.Fatalf("configured header = %q", got.source)
	}
	if got.contentType != "application/json" {
		t.Fatalf("content-type = %q", got.contentType)
	}
	alert, ok := got.body["alert"].(map[string]any)
	if !ok {
		t.Fatalf("body = %#v, want an alert object", got.body)
	}
	if alert["rule_id"] != "php2shell-upload" || alert["name"] != "PHP upload blocked" || alert["message"] != "multipart upload blocked" {
		t.Fatalf("alert body = %#v", alert)
	}
	if alert["value"] != float64(7) || alert["severity"] != "critical" {
		t.Fatalf("alert body = %#v", alert)
	}
}

func TestDelivererNotifyRejectsErrorStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream down")
	}))
	defer server.Close()

	pack := packForServer(t, server)
	deliverer, err := pack.New(config.NotifierConfig{To: "abc123", AllowPrivateEndpoint: true}, server.Client())
	if err != nil {
		t.Fatalf("build deliverer: %v", err)
	}
	err = deliverer.Notify(context.Background(), testAlert())
	if err == nil {
		t.Fatalf("notify accepted a 502 response")
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "upstream down") {
		t.Fatalf("error = %v, want status and bounded body detail", err)
	}
}

func TestDelivererNewRequiresRequiredValue(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	if _, err := pack.New(config.NotifierConfig{}, nil); err == nil || !strings.Contains(err.Error(), `required config value "to"`) {
		t.Fatalf("error = %v, want missing required value", err)
	}
}

func TestDelivererEndpointOverride(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/custom/hook" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pack, err := Parse([]byte(staticPackJSON))
	if err != nil {
		t.Fatalf("parse static pack: %v", err)
	}
	deliverer, err := pack.New(config.NotifierConfig{
		Endpoint:             server.URL + "/custom/hook",
		Token:                "pack-token",
		AllowPrivateEndpoint: true,
	}, server.Client())
	if err != nil {
		t.Fatalf("build deliverer: %v", err)
	}
	if want := server.URL + "/custom/hook"; deliverer.endpoint != want {
		t.Fatalf("endpoint = %q, want %q", deliverer.endpoint, want)
	}
	if err := deliverer.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("notify: %v", err)
	}
}

func TestDelivererEndpointOverrideRequiresHTTPS(t *testing.T) {
	pack, err := Parse([]byte(staticPackJSON))
	if err != nil {
		t.Fatalf("parse static pack: %v", err)
	}
	_, err = pack.New(config.NotifierConfig{Endpoint: "http://static.example.com/hook"}, nil)
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("error = %v, want https-only override rejection", err)
	}
}

func TestDelivererWithoutOverrideUsesTemplateURL(t *testing.T) {
	pack, err := Parse([]byte(staticPackJSON))
	if err != nil {
		t.Fatalf("parse static pack: %v", err)
	}
	deliverer, err := pack.New(config.NotifierConfig{}, nil)
	if err != nil {
		t.Fatalf("build deliverer: %v", err)
	}
	if deliverer.client == nil {
		t.Fatalf("guarded client not built")
	}
	if deliverer.client.Timeout != notifierTimeout {
		t.Fatalf("timeout = %v, want %v", deliverer.client.Timeout, notifierTimeout)
	}
	if deliverer.endpoint != "https://static.example.com/hook" {
		t.Fatalf("endpoint = %q", deliverer.endpoint)
	}
}

func TestDelivererNewRejectsPrivateEndpointWithoutOptIn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pack := packForServer(t, server)
	if _, err := pack.New(config.NotifierConfig{To: "abc123"}, server.Client()); err == nil {
		t.Fatalf("private endpoint accepted without allow_private_endpoint")
	}
	if _, err := pack.New(config.NotifierConfig{To: "abc123", AllowPrivateEndpoint: true}, server.Client()); err != nil {
		t.Fatalf("private endpoint rejected after opt-in: %v", err)
	}
}

func TestDelivererUsesOperatorConfigMapForDeclaredField(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/open-apis/bot/v2/hook/abc123" {
			t.Errorf("path = %q, want the cfg.Config value", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer pack-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	document := strings.Replace(validPackJSON, `"name": "to"`, `"name": "hook_id"`, 1)
	document = strings.Replace(document, `hook/{to}`, `hook/{hook_id}`, 1)
	document = strings.Replace(document, `"variables": ["to"]`, `"variables": ["hook_id"]`, 1)
	document = strings.Replace(document, "https://open.larksuite.com", server.URL, 1)
	pack, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	deliverer, err := pack.New(config.NotifierConfig{
		Config:               map[string]string{"hook_id": "abc123"},
		Token:                "pack-token",
		Headers:              map[string]string{"hook_id": "from-header"},
		AllowPrivateEndpoint: true,
	}, server.Client())
	if err != nil {
		t.Fatalf("build deliverer: %v", err)
	}
	if err := deliverer.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("notify: %v", err)
	}
}

func TestDelivererNotifyWithoutConfiguration(t *testing.T) {
	var nilDeliverer *Deliverer
	if err := nilDeliverer.Notify(context.Background(), testAlert()); err == nil {
		t.Fatalf("nil deliverer accepted an alert")
	}
	if err := (&Deliverer{}).Notify(context.Background(), testAlert()); err == nil {
		t.Fatalf("empty deliverer accepted an alert")
	}
}

func TestDelivererNotifyStopsWhenContextIsDone(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pack := packForServer(t, server)
	deliverer, err := pack.New(config.NotifierConfig{To: "abc123", AllowPrivateEndpoint: true}, server.Client())
	if err != nil {
		t.Fatalf("build deliverer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deliverer.Notify(ctx, testAlert()); err == nil {
		t.Fatalf("notify ignored a canceled context")
	}
}

func TestNewRevalidatesHandBuiltPack(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	pack.EndpointTemplates[0].URLTemplate = "https://open.larksuite.com/hook/{hook_id}"
	pack.EndpointTemplates[0].Variables = []string{"hook_id"}
	_, err = pack.New(config.NotifierConfig{To: "abc", AllowPrivateEndpoint: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "hook_id") {
		t.Fatalf("error = %v, want undeclared variable rejection", err)
	}
}
