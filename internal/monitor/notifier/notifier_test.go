package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("unexpected authorization header %q", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:                   "webhook",
		Type:                 "webhook",
		Endpoint:             server.URL,
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

func TestWebhookRequiresHTTPSForCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("credentialed notifier must not dial an HTTP endpoint")
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:                   "webhook",
		Type:                 "webhook",
		Endpoint:             server.URL,
		Token:                "test-token",
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}, server.Client())

	err := webhook.Notify(context.Background(), monitor.Alert{RuleID: "https-required"})
	if err == nil || !strings.Contains(err.Error(), "requires an HTTPS endpoint") {
		t.Fatalf("expected HTTPS credential guard error, got %v", err)
	}
}

func TestWebhookSignsAndRetriesTransientFailures(t *testing.T) {
	const secret = "test-secret"
	var requests int
	var firstBody, firstEventID, firstTimestamp, firstSignature string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
			t.Errorf("unexpected authorization header %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if requests == 1 {
			firstBody = string(body)
			firstEventID = r.Header.Get("X-Event-ID")
			firstTimestamp = r.Header.Get("X-Timestamp")
			firstSignature = r.Header.Get("X-Signature")
		} else {
			if string(body) != firstBody || r.Header.Get("X-Event-ID") != firstEventID || r.Header.Get("X-Timestamp") != firstTimestamp || r.Header.Get("X-Signature") != firstSignature {
				t.Errorf("retry changed signed event metadata")
			}
		}
		if requests == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:                   "signed-webhook",
		Type:                 "webhook",
		Endpoint:             server.URL,
		Token:                secret,
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}, server.Client())
	alert := monitor.Alert{RuleID: "cpu-high", Severity: "critical", Message: "threshold exceeded", StartsAt: time.Unix(123, 0).UTC()}
	if err := webhook.Notify(context.Background(), alert); err != nil {
		t.Fatalf("expected transient failure to recover: %v", err)
	}
	if requests != 2 {
		t.Fatalf("expected one retry, got %d requests", requests)
	}
	if _, err := strconv.ParseInt(firstTimestamp, 10, 64); err != nil {
		t.Fatalf("invalid timestamp %q: %v", firstTimestamp, err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(firstTimestamp + "." + firstBody))
	wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if firstSignature != wantSignature {
		t.Fatalf("unexpected webhook signature: got %q want %q", firstSignature, wantSignature)
	}
}

func TestWebhookStopsAfterLimitedTransientRetries(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:                   "retry-limit",
		Type:                 "webhook",
		Endpoint:             server.URL,
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}, server.Client())
	err := webhook.Notify(context.Background(), monitor.Alert{RuleID: "retry-limit"})
	if err == nil || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("expected bounded delivery failure, got %v", err)
	}
	if requests != 3 {
		t.Fatalf("expected three attempts, got %d", requests)
	}
}

func TestWebhookDoesNotRetryPermanentClientErrors(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	webhook := NewWebhook(config.NotifierConfig{
		ID:                   "permanent-error",
		Type:                 "webhook",
		Endpoint:             server.URL,
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}, server.Client())
	if err := webhook.Notify(context.Background(), monitor.Alert{RuleID: "permanent-error"}); err == nil {
		t.Fatal("expected permanent client error")
	}
	if requests != 1 {
		t.Fatalf("expected no retry for 401, got %d requests", requests)
	}
}
