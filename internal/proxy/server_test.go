package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
