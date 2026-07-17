package notifier

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

type notifierFunc func(context.Context, monitor.Alert) error

func (f notifierFunc) Notify(ctx context.Context, alert monitor.Alert) error {
	return f(ctx, alert)
}

func TestManagerContinuesAfterNotifierFailure(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	manager := &Manager{notifiers: []Notifier{
		notifierFunc(func(context.Context, monitor.Alert) error {
			firstCalls++
			return errors.New("first delivery failed")
		}),
		notifierFunc(func(context.Context, monitor.Alert) error {
			secondCalls++
			return nil
		}),
	}}

	err := manager.Notify(context.Background(), []monitor.Alert{{RuleID: "one"}, {RuleID: "two"}})
	if err == nil || !strings.Contains(err.Error(), "first delivery failed") {
		t.Fatalf("expected aggregated delivery error, got %v", err)
	}
	if firstCalls != 2 || secondCalls != 2 {
		t.Fatalf("all deliveries must be attempted: first=%d second=%d", firstCalls, secondCalls)
	}
}

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
