package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func notifierTestHandler(t *testing.T) *Handler {
	t.Helper()
	cfg := &config.Config{}
	cfg.Monitor.Notifiers = []config.NotifierConfig{
		{ID: "ops", Name: "Ops", Type: "webhook", Endpoint: "https://notify.example.test/hook", Token: "secret", Enabled: true},
		{ID: "off", Type: "telegram", Endpoint: "https://api.telegram.org", Token: "secret", Enabled: false},
	}
	return &Handler{Config: cfg}
}

func TestListNotifierProvidersHidesSecrets(t *testing.T) {
	h := notifierTestHandler(t)
	recorder := httptest.NewRecorder()
	h.ListNotifierProviders(recorder, httptest.NewRequest(http.MethodGet, "/monitor/notifiers", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, secret := range []string{"notify.example.test", "secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("provider listing leaked %q: %s", secret, body)
		}
	}
	var payload struct {
		Data struct {
			Providers []notifierProviderView `json:"providers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Providers) != 2 || !payload.Data.Providers[0].Configured {
		t.Fatalf("unexpected providers: %+v", payload.Data.Providers)
	}
}

func TestTestNotifierRejectsDisabledProvider(t *testing.T) {
	h := notifierTestHandler(t)
	body := strings.NewReader(`{"id":"off"}`)
	recorder := httptest.NewRecorder()
	h.TestNotifierProvider(recorder, httptest.NewRequest(http.MethodPost, "/monitor/notifiers/test", body))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestTestNotifierRejectsUnknownProvider(t *testing.T) {
	h := notifierTestHandler(t)
	recorder := httptest.NewRecorder()
	h.TestNotifierProvider(recorder, httptest.NewRequest(http.MethodPost, "/monitor/notifiers/test", strings.NewReader(`{"id":"missing"}`)))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
