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

func TestNightingalePostsCallbackEvent(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotAuth string
	var gotBody nightingaleEvent
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Errorf("unmarshal event: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.NotifierConfig{
		ID:       "n9e",
		Type:     "nightingale",
		Endpoint: server.URL + "/api/n9e/callback?channel=waf",
		Token:    "n9e-token",
	}
	alert := testAlert()
	if err := NewNightingale(cfg, server.Client()).Notify(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/api/n9e/callback" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotQuery != "channel=waf" {
		t.Fatalf("query = %q", gotQuery)
	}
	if gotAuth != "Bearer n9e-token" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotBody.Cate != "cheesewaf" || gotBody.RuleName != "Auth burst" {
		t.Fatalf("event = %#v", gotBody)
	}
	if gotBody.Severity != 1 {
		t.Fatalf("severity = %d", gotBody.Severity)
	}
	if gotBody.TriggerTime != alert.StartsAt.UTC().Unix() {
		t.Fatalf("trigger_time = %d", gotBody.TriggerTime)
	}
	if gotBody.TriggerValue != "12" {
		t.Fatalf("trigger_value = %q", gotBody.TriggerValue)
	}
	if gotBody.IsRecovered {
		t.Fatal("new alerts must not be marked recovered")
	}
	if gotBody.TagsMap["rule_id"] != "rule-1" || gotBody.TagsMap["source"] != "cheesewaf" {
		t.Fatalf("tags_map = %#v", gotBody.TagsMap)
	}
	foundRuleTag := false
	for _, tag := range gotBody.Tags {
		if tag == "rule_id=rule-1" {
			foundRuleTag = true
		}
	}
	if !foundRuleTag {
		t.Fatalf("tags = %#v", gotBody.Tags)
	}
	if gotBody.Annotations["message"] != "too many failures" || gotBody.Annotations["rule_id"] != "rule-1" {
		t.Fatalf("annotations = %#v", gotBody.Annotations)
	}
	body, _ := json.Marshal(gotBody)
	if strings.Contains(string(body), "n9e-token") {
		t.Fatal("token must not be part of the JSON body")
	}
}

func TestNightingaleSeverityMapping(t *testing.T) {
	cases := map[string]int{
		"critical": 1,
		"high":     1,
		"warning":  2,
		"medium":   2,
		"info":     3,
		"low":      3,
		"":         2,
	}
	for severity, want := range cases {
		if got := nightingaleSeverity(severity); got != want {
			t.Fatalf("nightingaleSeverity(%q) = %d, want %d", severity, got, want)
		}
	}
}

func TestNightingaleRequiresHTTPSWithToken(t *testing.T) {
	cfg := config.NotifierConfig{ID: "n9e", Endpoint: "http://n9e.example.test/callback", Token: "secret"}
	err := NewNightingale(cfg, http.DefaultClient).Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS rejection, got %v", err)
	}
}

func TestNightingaleAllowsHTTPWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := config.NotifierConfig{ID: "n9e", Endpoint: server.URL + "/callback"}
	if err := NewNightingale(cfg, server.Client()).Notify(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
}

func TestNightingaleHandlesNilAndEmptyConfig(t *testing.T) {
	var notifier *Nightingale
	if err := notifier.Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("nil notifier: %v", err)
	}
	if err := NewNightingale(config.NotifierConfig{}, nil).Notify(context.Background(), testAlert()); err != nil {
		t.Fatalf("empty endpoint: %v", err)
	}
	if _, err := nightingaleCallbackEndpoint(config.NotifierConfig{Endpoint: "ftp://n9e.example.test"}); err == nil {
		t.Fatal("expected invalid scheme rejection")
	}
}
