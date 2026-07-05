package notifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

func TestWebhookRejectsPrivateEndpointByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("notifier should not dial a private endpoint by default")
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:       "webhook",
		Type:     "webhook",
		Endpoint: server.URL,
		Enabled:  true,
	}, nil)

	err := webhook.Notify(context.Background(), monitor.Alert{RuleID: "blocked", StartsAt: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "notifier endpoint host IP must be public") {
		t.Fatalf("expected private endpoint guard error, got %v", err)
	}
}

func TestWebhookAllowsPrivateEndpointWhenExplicit(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:                   "webhook",
		Type:                 "webhook",
		Endpoint:             server.URL,
		Token:                "test-token",
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}, nil)

	if err := webhook.Notify(context.Background(), monitor.Alert{RuleID: "blocked", StartsAt: time.Now()}); err != nil {
		t.Fatalf("expected notifier to allow explicitly trusted private endpoint: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected one notifier request, got %d", requests)
	}
}
