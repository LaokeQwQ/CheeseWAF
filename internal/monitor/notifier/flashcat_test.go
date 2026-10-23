package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestFlashcatPostsStandardEvent(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotAuth string
	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.NotifierConfig{ID: "fc", Type: "flashcat", Endpoint: server.URL, Token: "fc-token"}
	if err := NewFlashcat(cfg, server.Client()).Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/event/push/alert/standard" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotQuery != "" {
		t.Fatalf("token must not leak into the URL, query = %q", gotQuery)
	}
	if gotAuth != "Bearer fc-token" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotBody["title_rule"] != "Auth burst" {
		t.Fatalf("title_rule = %#v", gotBody["title_rule"])
	}
	if gotBody["event_status"] != "Critical" {
		t.Fatalf("event_status = %#v", gotBody["event_status"])
	}
	if key, _ := gotBody["alert_key"].(string); !strings.HasPrefix(key, "cheesewaf-") {
		t.Fatalf("alert_key = %#v", gotBody["alert_key"])
	}
	labels, _ := gotBody["labels"].(map[string]any)
	if labels["source"] != "cheesewaf" || labels["rule_id"] != "rule-1" || labels["metric"] != "auth_failures" {
		t.Fatalf("labels = %#v", labels)
	}
	description, _ := gotBody["description"].(string)
	if !strings.Contains(description, "too many failures") {
		t.Fatalf("description = %q", description)
	}
	body, _ := json.Marshal(gotBody)
	if strings.Contains(string(body), "fc-token") {
		t.Fatal("token must not be part of the JSON body")
	}
}

func TestFlashcatPreservesDedicatedPushURL(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.NotifierConfig{
		ID:       "fc",
		Endpoint: server.URL + "/event/push/alert/standard?integration_key=integration-1",
		Token:    "fc-token",
	}
	if err := NewFlashcat(cfg, server.Client()).Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/event/push/alert/standard" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotQuery != "integration_key=integration-1" {
		t.Fatalf("query = %q", gotQuery)
	}
}

func TestFlashcatStatusMapping(t *testing.T) {
	cases := map[string]string{
		"critical": "Critical",
		"high":     "Critical",
		"warning":  "Warning",
		"medium":   "Warning",
		"info":     "Info",
		"low":      "Info",
		"ok":       "Ok",
		"":         "Warning",
	}
	for severity, want := range cases {
		if got := flashcatEventStatus(severity); got != want {
			t.Fatalf("flashcatEventStatus(%q) = %q, want %q", severity, got, want)
		}
	}
}

func TestFlashcatRequiresHTTPSWithToken(t *testing.T) {
	cfg := config.NotifierConfig{ID: "fc", Endpoint: "http://flashcat.example.test", Token: "secret"}
	err := NewFlashcat(cfg, http.DefaultClient).Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS rejection, got %v", err)
	}
}

func TestFlashcatAllowsHTTPWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := config.NotifierConfig{ID: "fc", Endpoint: server.URL}
	if err := NewFlashcat(cfg, server.Client()).Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
}

func TestFlashcatHandlesNilAndEmptyConfig(t *testing.T) {
	var notifier *Flashcat
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("nil notifier: %v", err)
	}
	if err := NewFlashcat(config.NotifierConfig{}, nil).Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("empty endpoint: %v", err)
	}
	if _, err := flashcatEventEndpoint(config.NotifierConfig{Endpoint: "ftp://flashcat.example.test"}); err == nil {
		t.Fatal("expected invalid scheme rejection")
	}
}
