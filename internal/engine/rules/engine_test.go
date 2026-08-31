package rules

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestEngineMatchesCustomRule(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "admin", Name: "Admin Probe", Pattern: `(?i)/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected custom rule block, got %+v", result)
	}
}

func TestFromConfigExtractsSafeLiteralPrefix(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "prefix", Name: "prefix", Pattern: `^/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 || compiled[0].literalPrefix != "/admin" {
		t.Fatalf("literal prefix = %q, want /admin", compiled[0].literalPrefix)
	}
}

func TestEngineSeparatesURIAndQueryLocations(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{
		{ID: "uri", Name: "URI", Pattern: `debug=true`, Location: "uri", Action: "block", Severity: "high", Enabled: true},
		{ID: "query", Name: "Query", Pattern: `debug=true`, Location: "query", Action: "challenge", Severity: "medium", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "/search?debug=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.DetectorID != "rules.custom.query" || result.Action != engine.ActionChallenge {
		t.Fatalf("query-only input must match the query rule: %+v", result)
	}
}

func TestEngineBlockBeatsEarlierLogMatch(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{
		{ID: "log", Name: "Log", Pattern: `probe`, Location: "uri", Action: "log", Severity: "low", Enabled: true, Priority: 10},
		{ID: "block", Name: "Block", Pattern: `probe`, Location: "uri", Action: "block", Severity: "high", Enabled: true, Priority: 20},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.DetectorID != "rules.custom.block" || result.Action != engine.ActionBlock {
		t.Fatalf("block rule must beat an earlier log rule: %+v", result)
	}
}

func TestEngineRedactsHeaderAndCookieMatchPayloads(t *testing.T) {
	for _, tc := range []struct {
		name     string
		location string
		setup    func(*http.Request)
	}{
		{
			name:     "header",
			location: "header",
			setup: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer secret-token")
			},
		},
		{
			name:     "cookie",
			location: "cookie",
			setup: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session", Value: "secret-token"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := FromConfig([]config.CustomRuleConfig{{
				ID: tc.name, Name: tc.name, Pattern: `secret-token`, Location: tc.location, Action: "block", Severity: "high", Enabled: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(req)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := New(compiled).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected {
				t.Fatalf("expected a %s match, got %+v", tc.location, result)
			}
			if strings.Contains(result.Payload, "secret-token") || strings.Contains(result.Payload, "Authorization") {
				t.Fatalf("sensitive %s value leaked into payload: %q", tc.location, result.Payload)
			}
		})
	}
}

func TestEngineClipsLongBodyPayload(t *testing.T) {
	needle := "EVIL_NEEDLE_TOKEN"
	// 4KB body with needle near the middle so a window around the match is required.
	prefix := strings.Repeat("A", 2000)
	suffix := strings.Repeat("B", 2000)
	body := prefix + needle + suffix

	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "long-body", Name: "Long Body Needle", Pattern: needle, Location: "body", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected {
		t.Fatalf("expected detection, got %+v", result)
	}
	if len(result.Payload) > 512 {
		t.Fatalf("Payload length %d exceeds 512-byte clip limit", len(result.Payload))
	}
	if !strings.Contains(result.Payload, needle) {
		t.Fatalf("clipped Payload lost match needle: %q", result.Payload)
	}
}

func TestFromStorageCompilesSiteCustomRules(t *testing.T) {
	compiled, err := FromStorage([]storage.Rule{{
		ID: "admin", SiteID: "default", Name: "Admin Probe", Pattern: `(?i)/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected custom rule block from storage, got %+v", result)
	}
}
