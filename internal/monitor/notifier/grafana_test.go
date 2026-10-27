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
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type grafanaAnnotation struct {
	Text string   `json:"text"`
	Tags []string `json:"tags"`
	Time int64    `json:"time"`
}

func TestGrafanaCreatesAnnotation(t *testing.T) {
	var gotPath, gotAuthorization, gotContentType, gotOrgID string
	var received grafanaAnnotation
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotOrgID = r.Header.Get("X-Scope-OrgID")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.NotifierConfig{
		ID:       "grafana",
		Type:     "grafana",
		Endpoint: server.URL + "/",
		Token:    "grafana-token",
		Headers:  map[string]string{"X-Scope-OrgID": "tenant-1"},
	}
	alert := testAlert()
	notifier, err := NewRegistry().New(cfg, server.Client())
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	if err := notifier.Notify(context.Background(), alert); err != nil {
		t.Fatalf("notify: %v", err)
	}

	if gotPath != "/api/annotations" {
		t.Fatalf("path = %q, want /api/annotations", gotPath)
	}
	if gotAuthorization != "Bearer grafana-token" {
		t.Fatalf("Authorization = %q", gotAuthorization)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if gotOrgID != "tenant-1" {
		t.Fatalf("X-Scope-OrgID = %q", gotOrgID)
	}
	for _, want := range []string{"PHP upload blocked", "[critical]", "multipart upload blocked"} {
		if !strings.Contains(received.Text, want) {
			t.Fatalf("text missing %q: %q", want, received.Text)
		}
	}
	for _, want := range []string{"cheesewaf", "severity:critical", "rule:php2shell-upload", "metric:cheesewaf_php2shell_blocks"} {
		if !slices.Contains(received.Tags, want) {
			t.Fatalf("tags %#v missing %q", received.Tags, want)
		}
	}
	if want := alert.StartsAt.UnixMilli(); received.Time != want {
		t.Fatalf("time = %d, want %d", received.Time, want)
	}
}

func TestGrafanaUsesNowWhenStartsAtMissing(t *testing.T) {
	fixed := time.Date(2026, 10, 24, 9, 30, 0, 0, time.UTC)
	var received grafanaAnnotation
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewRegistry().New(config.NotifierConfig{
		ID:       "grafana",
		Type:     "grafana",
		Endpoint: server.URL,
		Token:    "grafana-token",
	}, server.Client())
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	notifier, ok := provider.(*grafanaNotifier)
	if !ok {
		t.Fatalf("unexpected grafana provider type %T", provider)
	}
	notifier.now = func() time.Time { return fixed }

	alert := testAlert()
	alert.StartsAt = time.Time{}
	if err := notifier.Notify(context.Background(), alert); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if received.Time != fixed.UnixMilli() {
		t.Fatalf("time = %d, want %d", received.Time, fixed.UnixMilli())
	}
}

func TestGrafanaRequiresHTTPSForAPIToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("credentialed grafana notifier must not dial an HTTP endpoint")
	}))
	defer server.Close()

	notifier, err := NewRegistry().New(config.NotifierConfig{
		ID:       "grafana",
		Type:     "grafana",
		Endpoint: server.URL,
		Token:    "grafana-token",
	}, server.Client())
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected HTTPS credential guard error, got %v", err)
	}
}

func TestGrafanaAllowsPlainHTTPWithoutAPIToken(t *testing.T) {
	gotAuthorization := "unset"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewRegistry().New(config.NotifierConfig{
		ID:       "grafana",
		Type:     "grafana",
		Endpoint: server.URL,
	}, server.Client())
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if gotAuthorization != "" {
		t.Fatalf("Authorization = %q, want empty", gotAuthorization)
	}
}

func TestGrafanaReportsDeliveryFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	notifier, err := NewRegistry().New(config.NotifierConfig{
		ID:       "grafana",
		Type:     "grafana",
		Endpoint: server.URL,
		Token:    "grafana-token",
	}, server.Client())
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil {
		t.Fatal("expected delivery error")
	}
	for _, want := range []string{`"grafana"`, "401 Unauthorized"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestGrafanaRejectsInvalidEndpoint(t *testing.T) {
	notifier, err := NewRegistry().New(config.NotifierConfig{ID: "grafana", Type: "grafana", Endpoint: "not-a-url"}, nil)
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "absolute URL") {
		t.Fatalf("expected absolute URL error, got %v", err)
	}
}

func TestGrafanaSkipsEmptyEndpoint(t *testing.T) {
	notifier, err := NewRegistry().New(config.NotifierConfig{ID: "grafana", Type: "grafana"}, nil)
	if err != nil {
		t.Fatalf("create grafana provider: %v", err)
	}
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("expected no-op for empty endpoint, got %v", err)
	}
}
