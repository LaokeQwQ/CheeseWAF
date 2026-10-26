package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

type datadogEvent struct {
	Title          string   `json:"title"`
	Text           string   `json:"text"`
	AlertType      string   `json:"alert_type"`
	SourceTypeName string   `json:"source_type_name"`
	Tags           []string `json:"tags"`
}

func TestDatadogPublishesEvent(t *testing.T) {
	var gotPath, gotAPIKey, gotApplicationKey, gotContentType string
	var received datadogEvent
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("DD-API-KEY")
		gotApplicationKey = r.Header.Get("DD-APPLICATION-KEY")
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.NotifierConfig{
		ID:       "dd",
		Type:     "datadog",
		Endpoint: server.URL + "/",
		Token:    "dd-api-key",
		Headers:  map[string]string{"DD-APPLICATION-KEY": "dd-application-key"},
	}
	notifier, err := NewProvider(cfg, server.Client())
	if err != nil {
		t.Fatalf("create datadog provider: %v", err)
	}
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("notify: %v", err)
	}

	if gotPath != "/api/v1/events" {
		t.Fatalf("path = %q, want /api/v1/events", gotPath)
	}
	if gotAPIKey != "dd-api-key" {
		t.Fatalf("DD-API-KEY = %q", gotAPIKey)
	}
	if gotApplicationKey != "dd-application-key" {
		t.Fatalf("DD-APPLICATION-KEY = %q", gotApplicationKey)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if received.Title != "PHP upload blocked" {
		t.Fatalf("title = %q", received.Title)
	}
	for _, want := range []string{"PHP upload blocked", "cheesewaf_php2shell_blocks", "multipart upload blocked"} {
		if !strings.Contains(received.Text, want) {
			t.Fatalf("text missing %q: %q", want, received.Text)
		}
	}
	if received.AlertType != "error" {
		t.Fatalf("alert_type = %q, want error", received.AlertType)
	}
	if received.SourceTypeName != "cheesewaf" {
		t.Fatalf("source_type_name = %q", received.SourceTypeName)
	}
	for _, want := range []string{"source:cheesewaf", "severity:critical", "rule:php2shell-upload", "metric:cheesewaf_php2shell_blocks"} {
		if !slices.Contains(received.Tags, want) {
			t.Fatalf("tags %#v missing %q", received.Tags, want)
		}
	}
}

func TestDatadogRequiresHTTPSForAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("credentialed datadog notifier must not dial an HTTP endpoint")
	}))
	defer server.Close()

	notifier, err := NewProvider(config.NotifierConfig{
		ID:       "dd",
		Type:     "datadog",
		Endpoint: server.URL,
		Token:    "dd-api-key",
	}, server.Client())
	if err != nil {
		t.Fatalf("create datadog provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected HTTPS credential guard error, got %v", err)
	}
}

func TestDatadogAllowsPlainHTTPWithoutAPIKey(t *testing.T) {
	gotAPIKey := "unset"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("DD-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewProvider(config.NotifierConfig{
		ID:       "dd",
		Type:     "datadog",
		Endpoint: server.URL,
	}, server.Client())
	if err != nil {
		t.Fatalf("create datadog provider: %v", err)
	}
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if gotAPIKey != "" {
		t.Fatalf("DD-API-KEY = %q, want empty", gotAPIKey)
	}
}

func TestDatadogRejectsInvalidEndpoint(t *testing.T) {
	notifier, err := NewProvider(config.NotifierConfig{ID: "dd", Type: "datadog", Endpoint: "not-a-url"}, nil)
	if err != nil {
		t.Fatalf("create datadog provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "absolute URL") {
		t.Fatalf("expected absolute URL error, got %v", err)
	}
}

func TestDatadogReportsDeliveryFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier, err := NewProvider(config.NotifierConfig{
		ID:       "dd",
		Type:     "datadog",
		Endpoint: server.URL,
		Token:    "dd-api-key",
	}, server.Client())
	if err != nil {
		t.Fatalf("create datadog provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil {
		t.Fatal("expected delivery error")
	}
	for _, want := range []string{`"dd"`, "400 Bad Request"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestDatadogSkipsEmptyEndpoint(t *testing.T) {
	notifier, err := NewProvider(config.NotifierConfig{ID: "dd", Type: "datadog"}, nil)
	if err != nil {
		t.Fatalf("create datadog provider: %v", err)
	}
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("expected no-op for empty endpoint, got %v", err)
	}
}

func TestDatadogAlertTypeMapping(t *testing.T) {
	cases := map[string]string{
		"critical": "error",
		"high":     "error",
		"warning":  "warning",
		"medium":   "warning",
		"low":      "info",
		"":         "info",
		"success":  "success",
	}
	for severity, want := range cases {
		if got := datadogAlertType(severity); got != want {
			t.Fatalf("datadogAlertType(%q) = %q, want %q", severity, got, want)
		}
	}
}

func TestDatadogTagsAvoidInvalidCharacters(t *testing.T) {
	tags := datadogAlertTags(monitor.Alert{RuleID: "rule with,comma", Metric: " m\t1 "})
	for _, tag := range tags {
		if strings.ContainsAny(tag, " ,\t") {
			t.Fatalf("tag %q contains invalid characters: %#v", tag, tags)
		}
	}
}
