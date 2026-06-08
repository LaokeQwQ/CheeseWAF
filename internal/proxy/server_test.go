package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestServerPassesAndBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewSQLDetector("block"), semantic.NewXSSDetector("block")), noopSink{})
	if err != nil {
		t.Fatal(err)
	}

	passReq := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	passRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(passRec, passReq)
	if passRec.Code != http.StatusOK || strings.TrimSpace(passRec.Body.String()) != "ok" {
		t.Fatalf("expected proxy pass, code=%d body=%q", passRec.Code, passRec.Body.String())
	}

	blockReq := httptest.NewRequest(http.MethodGet, "http://localhost/?id=1%27%20OR%20%271%27%3D%271", nil)
	blockRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(blockRec, blockReq)
	if blockRec.Code != http.StatusForbidden {
		t.Fatalf("expected block, code=%d body=%q", blockRec.Code, blockRec.Body.String())
	}
}

func TestServerWebAttackPolicyLevels(t *testing.T) {
	result := &engine.DetectionResult{
		Detected:   true,
		DetectorID: "test.semantic",
		Category:   "sqli",
		Severity:   engine.SeverityHigh,
		Action:     engine.ActionBlock,
		Message:    "test detection",
		Confidence: 0.88,
		Payload:    "id=1 or 1=1",
	}

	t.Run("smart blocks high confidence high severity", func(t *testing.T) {
		server, sink, cleanup := newPolicyTestServer(t, config.ProtectionLevelSmart, result)
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/?id=1", nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected smart policy block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].Category != "sqli" {
			t.Fatalf("unexpected smart policy log entries: %#v", sink.entries)
		}
	})

	t.Run("low records but passes high severity below threshold", func(t *testing.T) {
		server, sink, cleanup := newPolicyTestServer(t, config.ProtectionLevelLow, result)
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/?id=1", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected low policy pass, code=%d", recorder.Code)
		}
		if strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected upstream response, body=%q", recorder.Body.String())
		}
		if len(sink.entries) != 1 {
			t.Fatalf("expected one log entry, got %d", len(sink.entries))
		}
		entry := sink.entries[0]
		if entry.Action != "log" || entry.Category != "sqli" || entry.Severity != "high" || entry.DetectorID != "test.semantic" {
			t.Fatalf("unexpected low policy log entry: %#v", entry)
		}
		decision, ok := entry.Metadata["waf_policy_decision"].(webAttackPolicyDecision)
		if !ok {
			t.Fatalf("missing policy decision metadata: %#v", entry.Metadata)
		}
		if decision.Level != config.ProtectionLevelLow || decision.Action != engine.ActionLog.String() || decision.MinimumSeverity != "critical" {
			t.Fatalf("unexpected policy decision: %#v", decision)
		}
	})

	t.Run("detector log action is not escalated by strict policy", func(t *testing.T) {
		logOnly := *result
		logOnly.Action = engine.ActionLog
		server, sink, cleanup := newPolicyTestServer(t, config.ProtectionLevelStrict, &logOnly)
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/?id=1", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected strict policy to respect detector log action, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "log" {
			t.Fatalf("unexpected strict log-only entries: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["waf_policy_decision"].(webAttackPolicyDecision)
		if !ok || decision.Action != engine.ActionLog.String() || decision.Reason != "detector requested log" {
			t.Fatalf("unexpected strict log-only decision: %#v", sink.entries[0].Metadata)
		}
	})

	t.Run("detector challenge action is preserved when threshold matches", func(t *testing.T) {
		challenge := *result
		challenge.Action = engine.ActionChallenge
		challenge.Category = "custom_rule"
		challenge.Confidence = 0.91
		server, sink, cleanup := newPolicyTestServer(t, config.ProtectionLevelSmart, &challenge)
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/?id=1", nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected challenge response, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "challenge" || sink.entries[0].Category != "custom_rule" {
			t.Fatalf("unexpected challenge entries: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["waf_policy_decision"].(webAttackPolicyDecision)
		if !ok || decision.Action != engine.ActionChallenge.String() {
			t.Fatalf("unexpected challenge decision: %#v", sink.entries[0].Metadata)
		}
	})
}

func TestServerThreatIntelPolicyLevels(t *testing.T) {
	t.Run("smart challenges high confidence threat intel match", func(t *testing.T) {
		server, sink, cleanup := newThreatIntelTestServer(t, config.ProtectionLevelSmart, []config.ThreatIntelConfig{{
			ID: "feed-1", Value: "203.0.113.10", Severity: "high", Source: "feed-a", Action: "challenge", Confidence: 0.9, Enabled: true,
		}}, nil)
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.10")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected threat intel challenge, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "challenge" || sink.entries[0].Category != "threat_intel" {
			t.Fatalf("unexpected threat intel challenge log: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["threat_intel_decision"].(ip.ThreatDecision)
		if !ok || decision.Action != "challenge" || decision.Score < decision.MinimumScore {
			t.Fatalf("unexpected threat intel decision: %#v", sink.entries[0].Metadata)
		}
	})

	t.Run("low records but passes below threat intel threshold", func(t *testing.T) {
		server, sink, cleanup := newThreatIntelTestServer(t, config.ProtectionLevelLow, []config.ThreatIntelConfig{{
			ID: "feed-1", Value: "203.0.113.10", Severity: "high", Source: "feed-a", Action: "block", Confidence: 0.9, Enabled: true,
		}}, nil)
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.10")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected low policy pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "log" || sink.entries[0].Category != "threat_intel" {
			t.Fatalf("unexpected low threat intel log: %#v", sink.entries)
		}
	})

	t.Run("whitelist bypasses threat intel match", func(t *testing.T) {
		server, sink, cleanup := newThreatIntelTestServer(t, config.ProtectionLevelSmart, []config.ThreatIntelConfig{{
			ID: "feed-1", Value: "203.0.113.10", Severity: "critical", Source: "feed-a", Action: "block", Confidence: 1, Enabled: true,
		}}, []string{"203.0.113.10"})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.10")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected whitelist pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Category == "threat_intel" {
			t.Fatalf("unexpected threat intel log for whitelisted ip: %#v", sink.entries)
		}
	})
}

func TestServerScopedIPAccessRuleBlocksBeforeUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.IP.AccessRules = []config.IPAccessRuleConfig{{
		ID:         "block-admin-ip",
		Name:       "Block admin probes",
		Action:     "block",
		Scope:      "path",
		SiteID:     "default",
		PathPrefix: "/admin",
		Entries:    []string{"192.0.2.1"},
		Enabled:    true,
	}}
	cfg.Protection.RateLimit.Enabled = false
	sink := &captureSink{}
	server, err := NewServer(&cfg, engine.NewPipeline(), sink)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/admin", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected access rule block, code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if len(sink.entries) != 1 || sink.entries[0].Category != "ip_access" || sink.entries[0].Action != "block" {
		t.Fatalf("unexpected access rule log: %#v", sink.entries)
	}
}

func TestServerBotCCPolicyLevels(t *testing.T) {
	t.Run("smart challenges suspicious bot traffic", func(t *testing.T) {
		server, sink, cleanup := newBotCCTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.Protection.Bot.Enabled = true
			cfg.Protection.Bot.JSChallenge = true
			cfg.Protection.RateLimit.Enabled = false
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/probe", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected smart bot challenge, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "challenge" || sink.entries[0].Category != "bot" {
			t.Fatalf("unexpected smart bot log: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["bot_cc_policy_decision"].(botCCPolicyDecision)
		if !ok || decision.Action != engine.ActionChallenge.String() {
			t.Fatalf("unexpected bot decision: %#v", sink.entries[0].Metadata)
		}
	})

	t.Run("low records but passes suspicious bot traffic", func(t *testing.T) {
		server, sink, cleanup := newBotCCTestServer(t, config.ProtectionLevelLow, func(cfg *config.Config) {
			cfg.Protection.Bot.Enabled = true
			cfg.Protection.Bot.JSChallenge = true
			cfg.Protection.RateLimit.Enabled = false
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/probe", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected low bot policy pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "log" || sink.entries[0].Category != "bot" {
			t.Fatalf("unexpected low bot log: %#v", sink.entries)
		}
	})

	t.Run("waiting room remains enforced when explicitly enabled", func(t *testing.T) {
		server, sink, cleanup := newBotCCTestServer(t, config.ProtectionLevelLow, func(cfg *config.Config) {
			cfg.Protection.Bot.Enabled = true
			cfg.Protection.Bot.WaitingRoom = true
			cfg.Protection.Bot.JSChallenge = false
			cfg.Protection.Bot.CAPTCHA = false
			cfg.Protection.RateLimit.Enabled = false
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/probe", nil))
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("expected waiting room response, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "challenge" || sink.entries[0].Category != "waiting_room" {
			t.Fatalf("unexpected waiting room log: %#v", sink.entries)
		}
	})

	t.Run("low records but passes rate limit breach", func(t *testing.T) {
		server, sink, cleanup := newBotCCTestServer(t, config.ProtectionLevelLow, func(cfg *config.Config) {
			cfg.Protection.Bot.Enabled = false
			cfg.Protection.RateLimit.Enabled = true
			cfg.Protection.RateLimit.Default = config.RateLimitProfile{Requests: 1, Burst: 1}
		})
		defer cleanup()

		for idx := 0; idx < 3; idx++ {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/probe", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected low rate limit policy pass on request %d, code=%d", idx+1, recorder.Code)
			}
		}
		if len(sink.entries) != 3 || sink.entries[2].Action != "log" || sink.entries[2].Category != "ratelimit" {
			t.Fatalf("unexpected low rate limit logs: %#v", sink.entries)
		}
	})

	t.Run("smart blocks rate limit breach", func(t *testing.T) {
		server, sink, cleanup := newBotCCTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.Protection.Bot.Enabled = false
			cfg.Protection.RateLimit.Enabled = true
			cfg.Protection.RateLimit.Default = config.RateLimitProfile{Requests: 1, Burst: 1}
		})
		defer cleanup()

		for idx := 0; idx < 2; idx++ {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/probe", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected initial rate limit request %d to pass, code=%d", idx+1, recorder.Code)
			}
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/probe", nil))
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("expected smart rate limit block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 3 || sink.entries[2].Action != "block" || sink.entries[2].Category != "ratelimit" {
			t.Fatalf("unexpected smart rate limit logs: %#v", sink.entries)
		}
	})
}

func TestServerAPISecurityPolicyLevels(t *testing.T) {
	t.Run("smart blocks schema validation finding", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Validation.Enabled = true
			cfg.APISec.Validation.Schemas = []config.APIEndpointSchemaConfig{{
				ID: "search", Method: http.MethodGet, PathPattern: "^/api/search$", RequiredParams: []string{"q"}, Enabled: true,
			}}
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search", nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected smart API validation block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].Category != "apisec" {
			t.Fatalf("unexpected API validation log: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["api_security_policy_decision"].(apiSecurityPolicyDecision)
		if !ok || decision.Action != engine.ActionBlock.String() || decision.SchemaID != "search" || decision.Field != "q" {
			t.Fatalf("unexpected API security decision: %#v", sink.entries[0].Metadata)
		}
	})

	t.Run("low records but passes schema validation finding", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelLow, func(cfg *config.Config) {
			cfg.APISec.Validation.Enabled = true
			cfg.APISec.Validation.Schemas = []config.APIEndpointSchemaConfig{{
				ID: "search", Method: http.MethodGet, PathPattern: "^/api/search$", RequiredParams: []string{"q"}, Enabled: true,
			}}
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search", nil))
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected low API validation pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "log" || sink.entries[0].Category != "apisec" {
			t.Fatalf("unexpected low API validation log: %#v", sink.entries)
		}
	})

	t.Run("smart blocks API endpoint rate limit breach", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.RateLimits = []config.APIEndpointLimitConfig{{
				ID: "search-rate", Method: http.MethodGet, PathPattern: "^/api/search$", Requests: 1, Window: time.Minute, Enabled: true,
			}}
		})
		defer cleanup()

		for idx := 0; idx < 1; idx++ {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search?q=a", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected first API request to pass, code=%d", recorder.Code)
			}
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search?q=a", nil))
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("expected smart API rate limit block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 2 || sink.entries[1].Action != "block" || sink.entries[1].DetectorID != "apisec.ratelimit" {
			t.Fatalf("unexpected API rate limit logs: %#v", sink.entries)
		}
	})

	t.Run("low records but passes API endpoint rate limit breach", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelLow, func(cfg *config.Config) {
			cfg.APISec.RateLimits = []config.APIEndpointLimitConfig{{
				ID: "search-rate", Method: http.MethodGet, PathPattern: "^/api/search$", Requests: 1, Window: time.Minute, Enabled: true,
			}}
		})
		defer cleanup()

		for idx := 0; idx < 2; idx++ {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search?q=a", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected low API rate limit pass on request %d, code=%d", idx+1, recorder.Code)
			}
		}
		if len(sink.entries) != 2 || sink.entries[1].Action != "log" || sink.entries[1].DetectorID != "apisec.ratelimit" {
			t.Fatalf("unexpected low API rate limit logs: %#v", sink.entries)
		}
	})

	t.Run("runtime update refreshes API validation", func(t *testing.T) {
		server, _, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Enabled = false
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected API security disabled before update, code=%d", recorder.Code)
		}

		err := server.UpdateAPISec(config.APISecConfig{
			Enabled: true,
			Validation: config.APIValidationConfig{
				Enabled: true,
				Schemas: []config.APIEndpointSchemaConfig{{
					ID: "search", Method: http.MethodGet, PathPattern: "^/api/search$", RequiredParams: []string{"q"}, Enabled: true,
				}},
			},
		})
		if err != nil {
			t.Fatalf("update API security: %v", err)
		}

		recorder = httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/search", nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected API validation block after update, code=%d", recorder.Code)
		}
	})

	t.Run("runtime update rejects invalid API schema without replacing current state", func(t *testing.T) {
		server, _, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Enabled = false
		})
		defer cleanup()

		err := server.UpdateAPISec(config.APISecConfig{
			Enabled: true,
			Validation: config.APIValidationConfig{
				Enabled: true,
				Schemas: []config.APIEndpointSchemaConfig{{
					ID: "bad", Method: http.MethodGet, PathPattern: "(", RequiredParams: []string{"q"}, Enabled: true,
				}},
			},
		})
		if err == nil {
			t.Fatal("expected invalid API schema update to fail")
		}
		if server.config.APISec.Enabled {
			t.Fatalf("expected invalid update to preserve previous API security state: %+v", server.config.APISec)
		}
	})

	t.Run("smart blocks missing API auth token", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTIssuers = []string{"issuer-a"}
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected missing API auth token block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].DetectorID != "apisec.auth.missing" {
			t.Fatalf("unexpected missing auth log: %#v", sink.entries)
		}
	})

	t.Run("low records but passes missing API auth token", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelLow, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil))
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected low API auth pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "log" || sink.entries[0].DetectorID != "apisec.auth.missing" {
			t.Fatalf("unexpected low missing auth log: %#v", sink.entries)
		}
	})

	t.Run("smart passes API auth token with issuer and scope", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTIssuers = []string{"issuer-a"}
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testJWT(t, map[string]any{"iss": "issuer-a", "scope": []string{"orders:read"}}))
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected valid API auth pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Category == "apisec" {
			t.Fatalf("unexpected API auth finding for valid token: %#v", sink.entries)
		}
	})

	t.Run("smart blocks API auth token with invalid signature", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTIssuers = []string{"issuer-a"}
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testHMACJWT(t, "wrong-secret", map[string]any{"iss": "issuer-a", "scope": []string{"orders:read"}}))
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected invalid API auth signature block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].DetectorID != "apisec.auth.signature" {
			t.Fatalf("unexpected invalid signature log: %#v", sink.entries)
		}
	})

	t.Run("smart passes API auth token with valid signature", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTIssuers = []string{"issuer-a"}
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testHMACJWT(t, "proxy-secret", map[string]any{"iss": "issuer-a", "scope": []string{"orders:read"}}))
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected valid signed API auth pass, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Category == "apisec" {
			t.Fatalf("unexpected API auth finding for valid signed token: %#v", sink.entries)
		}
	})

	t.Run("smart blocks API auth token with invalid audience", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTIssuers = []string{"issuer-a"}
			cfg.APISec.Auth.JWTAudiences = []string{"orders-api"}
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testHMACJWT(t, "proxy-secret", map[string]any{"iss": "issuer-a", "aud": "other-api", "scope": []string{"orders:read"}}))
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected invalid API auth audience block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].DetectorID != "apisec.auth.audience" {
			t.Fatalf("unexpected invalid audience log: %#v", sink.entries)
		}
	})

	t.Run("smart blocks missing API auth scope", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTIssuers = []string{"issuer-a"}
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testJWT(t, map[string]any{"iss": "issuer-a", "scope": []string{"orders:write"}}))
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected missing API auth scope block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].DetectorID != "apisec.auth.scope" {
			t.Fatalf("unexpected missing scope log: %#v", sink.entries)
		}
	})

	t.Run("API auth does not apply to ordinary site path", func(t *testing.T) {
		server, sink, cleanup := newAPISecurityTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.RequiredScopes = []string{"orders:read"}
		})
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
			t.Fatalf("expected ordinary path to pass API auth check, code=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if len(sink.entries) != 1 || sink.entries[0].Category == "apisec" {
			t.Fatalf("unexpected API auth finding for ordinary path: %#v", sink.entries)
		}
	})
}

func TestServerPhase2Protections(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		_, _ = w.Write([]byte("password=secret"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "old", Pattern: "^/old/(.*)$", Replacement: "/new/$1", Enabled: true}}
	cfg.Sites[0].WAF.Response.Enabled = true
	cfg.Sites[0].WAF.Response.SensitivePatterns = []string{`password=secret`}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	cfg.Protection.ACL.Enabled = true
	cfg.Protection.ACL.Rules = []config.ACLRuleConfig{{ID: "debug", Name: "Debug", PathPrefix: "/debug", Action: "block", Enabled: true}}

	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}

	aclReq := httptest.NewRequest(http.MethodGet, "http://localhost/debug/vars", nil)
	aclRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(aclRec, aclReq)
	if aclRec.Code != http.StatusForbidden {
		t.Fatalf("expected ACL block, code=%d", aclRec.Code)
	}

	rewriteReq := httptest.NewRequest(http.MethodGet, "http://localhost/old/item", nil)
	rewriteRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rewriteRec, rewriteReq)
	if rewriteRec.Header().Get("X-Upstream-Path") != "/new/item" {
		t.Fatalf("rewrite did not reach upstream path: %s", rewriteRec.Header().Get("X-Upstream-Path"))
	}
	if rewriteRec.Header().Get("X-CheeseWAF-Response-Finding") == "" {
		t.Fatal("expected response inspection header")
	}
}

type noopSink struct{}

func (noopSink) Write(context.Context, *storage.LogEntry) error { return nil }
func (noopSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}
func (noopSink) Flush(context.Context) error { return nil }
func (noopSink) Close() error                { return nil }

type captureSink struct {
	entries []*storage.LogEntry
}

func (s *captureSink) Write(_ context.Context, entry *storage.LogEntry) error {
	s.entries = append(s.entries, entry)
	return nil
}

func (s *captureSink) Query(context.Context, storage.LogFilter) ([]storage.LogEntry, int64, error) {
	return nil, 0, nil
}

func (s *captureSink) Flush(context.Context) error { return nil }
func (s *captureSink) Close() error                { return nil }

type staticDetector struct {
	result *engine.DetectionResult
}

func (d staticDetector) ID() string    { return "test.semantic" }
func (d staticDetector) Name() string  { return "Test Semantic Detector" }
func (d staticDetector) Priority() int { return 1 }
func (d staticDetector) Detect(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) {
	return d.result, nil
}

func newPolicyTestServer(t *testing.T, level string, result *engine.DetectionResult) (*Server, *captureSink, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.Policy.WebAttack = level
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	sink := &captureSink{}
	server, err := NewServer(&cfg, engine.NewPipeline(staticDetector{result: result}), sink)
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	return server, sink, upstream.Close
}

func newThreatIntelTestServer(t *testing.T, level string, intel []config.ThreatIntelConfig, whitelist []string) (*Server, *captureSink, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.AccessControl.TrustedCIDRs = []string{"192.0.2.1"}
	cfg.Protection.Policy.ThreatIntel = level
	cfg.Protection.IP.ThreatIntel = intel
	cfg.Protection.IP.Whitelist = whitelist
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	sink := &captureSink{}
	server, err := NewServer(&cfg, engine.NewPipeline(), sink)
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	return server, sink, upstream.Close
}

func newBotCCTestServer(t *testing.T, level string, configure func(*config.Config)) (*Server, *captureSink, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.Policy.BotCC = level
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	if configure != nil {
		configure(&cfg)
	}
	sink := &captureSink{}
	server, err := NewServer(&cfg, engine.NewPipeline(), sink)
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	return server, sink, upstream.Close
}

func newAPISecurityTestServer(t *testing.T, level string, configure func(*config.Config)) (*Server, *captureSink, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.Policy.APISecurity = level
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	cfg.Protection.Bot.Enabled = false
	cfg.APISec.Enabled = true
	cfg.APISec.Validation.Enabled = false
	cfg.APISec.Validation.Schemas = nil
	cfg.APISec.RateLimits = nil
	if configure != nil {
		configure(&cfg)
	}
	sink := &captureSink{}
	server, err := NewServer(&cfg, engine.NewPipeline(), sink)
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	return server, sink, upstream.Close
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func testHMACJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
