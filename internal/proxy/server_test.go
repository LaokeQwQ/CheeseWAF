package proxy

import (
	"bytes"
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

func TestServerRejectsKnownLengthBodyBeforeUpstream(t *testing.T) {
	assertOversizedRequestRejected(t, false)
}

func TestServerRejectsChunkedBodyBeforeUpstream(t *testing.T) {
	assertOversizedRequestRejected(t, true)
}

func assertOversizedRequestRejected(t *testing.T, chunked bool) {
	t.Helper()
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.Performance.MaxBodyBytes = 8
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/upload", strings.NewReader("123456789"))
	if chunked {
		req.ContentLength = -1
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%q", recorder.Code, recorder.Body.String())
	}
	if upstreamHits != 0 {
		t.Fatalf("oversized request reached upstream %d times", upstreamHits)
	}
}

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

func TestServerBlockPageUsesRequestLanguage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewSQLDetector("block")), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?id=1%27%20OR%201=1", nil)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.1")
	req.Header.Set("Sec-CH-Timezone", "Asia/Shanghai")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected block, code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{"访问已被拦截", "安全策略已执行", "Asia/Shanghai"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected localized block page to contain %q, body=%s", want, body)
		}
	}
}

func TestServerStreamsLargeCompressibleResponseWhenCaptureLimitExceeded(t *testing.T) {
	body := strings.Repeat("large-response-", 512)
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.Performance.MaxBodyBytes = 256
	cfg.Sites[0].WAF.Response.Enabled = false
	cfg.Edge.Cache.Enabled = false
	cfg.Edge.Compression.Enabled = true
	cfg.Edge.Compression.MinBytes = 1
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false

	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/large.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected streaming fallback success, code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != body {
		t.Fatalf("expected full untruncated fallback body, got %d bytes", recorder.Body.Len())
	}
	if recorder.Header().Get("Content-Encoding") != "" {
		t.Fatalf("large fallback response should skip in-memory compression, got %q", recorder.Header().Get("Content-Encoding"))
	}
	if upstreamHits != 1 {
		t.Fatalf("expected a single upstream request when capture spills to streaming, got %d upstream hits", upstreamHits)
	}
}

func TestServerHotReloadsBlockPageTemplate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewSQLDetector("block")), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.UpdateBlockPage(config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body>custom-block {{.TraceID}} {{.AttackType}}</body></html>`,
	}); err != nil {
		t.Fatalf("update block page: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?id=1%27%20OR%201=1", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected block, code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "custom-block") || !strings.Contains(recorder.Body.String(), "sqli") {
		t.Fatalf("expected hot-reloaded custom block page, body=%q", recorder.Body.String())
	}
}

func TestServerProxyErrorsExposeTraceIDAndWriteEvent(t *testing.T) {
	cfg := config.Default()
	cfg.Sites[0].Upstreams = nil
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	sink := &captureSink{}

	server, err := NewServer(&cfg, engine.NewPipeline(), sink)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	traceID := recorder.Header().Get("X-CheeseWAF-Trace-ID")
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected proxy error, code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if traceID == "" {
		t.Fatal("expected proxy error trace header")
	}
	if !strings.Contains(recorder.Body.String(), traceID) || !strings.Contains(recorder.Body.String(), "Event / Trace ID") {
		t.Fatalf("expected proxy error body to include event trace id %q, body=%q", traceID, recorder.Body.String())
	}
	if len(sink.entries) != 1 {
		t.Fatalf("expected one proxy error log entry, got %d", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.ID != traceID || entry.TraceID != traceID || entry.Action != "error" || entry.Category != "proxy_error" {
		t.Fatalf("unexpected proxy error log entry: %#v", entry)
	}
	if entry.Metadata["proxy_error"] != "no upstream" {
		t.Fatalf("missing proxy error metadata: %#v", entry.Metadata)
	}
}

func TestServerUpstreamTransportErrorsExposeTraceIDAndWriteEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	upstreamURL := upstream.URL
	upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstreamURL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	sink := &captureSink{}

	server, err := NewServer(&cfg, engine.NewPipeline(), sink)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	traceID := recorder.Header().Get("X-CheeseWAF-Trace-ID")
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected upstream transport error, code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if traceID == "" {
		t.Fatal("expected upstream transport error trace header")
	}
	if !strings.Contains(recorder.Body.String(), traceID) || !strings.Contains(recorder.Body.String(), "Event / Trace ID") {
		t.Fatalf("expected upstream transport error body to include event trace id %q, body=%q", traceID, recorder.Body.String())
	}
	if len(sink.entries) != 1 {
		t.Fatalf("expected one upstream transport error log entry, got %d", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.ID != traceID || entry.TraceID != traceID || entry.Action != "error" || entry.Category != "proxy_error" {
		t.Fatalf("unexpected upstream transport error log entry: %#v", entry)
	}
	if entry.Metadata["proxy_error"] != "upstream proxy error" {
		t.Fatalf("missing upstream proxy error metadata: %#v", entry.Metadata)
	}
	if _, ok := entry.Metadata["proxy_error_detail"].(string); !ok {
		t.Fatalf("missing upstream proxy error detail: %#v", entry.Metadata)
	}
}

func TestServerBlocksSemanticPostBodyPayloads(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream method unsupported", http.StatusNotImplemented)
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false

	server, err := NewServer(&cfg, engine.NewPipeline(
		semantic.NewAnalyzer("block", "nosqli", "ssti"),
	), &captureSink{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		target      string
		contentType string
		body        string
		category    string
	}{
		{
			name:        "nosqli json login bypass",
			target:      "http://localhost/login",
			contentType: "application/json",
			body:        `{"username":{"$ne":null},"password":{"$ne":null}}`,
			category:    "nosqli",
		},
		{
			name:        "ssti form object graph execution",
			target:      "http://localhost/profile",
			contentType: "application/x-www-form-urlencoded",
			body:        `display_name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`,
			category:    "ssti",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.target, bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			recorder := httptest.NewRecorder()

			server.Handler().ServeHTTP(recorder, req)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected WAF block before upstream 501, code=%d body=%q", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.category) {
				t.Fatalf("expected block page to mention category %q, body=%q", tc.category, recorder.Body.String())
			}
		})
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

	t.Run("detection budget closed challenge bypasses severity gate", func(t *testing.T) {
		budget := &engine.DetectionResult{
			Detected:   true,
			DetectorID: "pipeline.budget",
			Category:   "detection_budget",
			Severity:   engine.SeverityMedium,
			Action:     engine.ActionChallenge,
			Confidence: 0.55,
			Message:    "detection budget exhausted",
		}
		decision := evaluateWebAttackPolicyWithEvidence(config.ProtectionLevelSmart, budget, nil)
		if decision.Action != engine.ActionChallenge.String() {
			t.Fatalf("budget closed must honor challenge without severity gate, got %#v", decision)
		}
		if decision.Reason == "" || decision.DetectorCategory != "detection_budget" {
			t.Fatalf("unexpected budget decision: %#v", decision)
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

	t.Run("smart uses aggregate evidence when single result is below direct threshold", func(t *testing.T) {
		sqli := *result
		sqli.DetectorID = "semantic.sqli"
		sqli.Confidence = 0.82
		xss := *result
		xss.DetectorID = "semantic.xss"
		xss.Category = "xss"
		xss.Severity = engine.SeverityMedium
		xss.Confidence = 0.75
		xss.Payload = "<svg onload=alert(1)>"
		server, sink, cleanup := newPolicyTestServerWithDetectors(t, config.ProtectionLevelSmart,
			staticDetector{result: &sqli, priority: 300},
			staticDetector{result: &xss, priority: 310},
		)
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/?id=1", nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("expected aggregate evidence block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "block" || sink.entries[0].Category != "sqli" {
			t.Fatalf("unexpected aggregate evidence log entry: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["waf_policy_decision"].(webAttackPolicyDecision)
		if !ok {
			t.Fatalf("missing aggregate policy decision: %#v", sink.entries[0].Metadata)
		}
		if decision.Reason != "aggregate risk score meets policy threshold" || decision.EvidenceCount != 2 || decision.RiskScore < decision.MinimumRiskScore {
			t.Fatalf("unexpected aggregate policy decision: %#v", decision)
		}
	})

	t.Run("low keeps aggregate evidence as log below conservative threshold", func(t *testing.T) {
		sqli := *result
		sqli.DetectorID = "semantic.sqli"
		sqli.Confidence = 0.82
		xss := *result
		xss.DetectorID = "semantic.xss"
		xss.Category = "xss"
		xss.Severity = engine.SeverityMedium
		xss.Confidence = 0.75
		xss.Payload = "<svg onload=alert(1)>"
		server, sink, cleanup := newPolicyTestServerWithDetectors(t, config.ProtectionLevelLow,
			staticDetector{result: &sqli, priority: 300},
			staticDetector{result: &xss, priority: 310},
		)
		defer cleanup()

		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/?id=1", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected low policy to avoid aggregate block, code=%d", recorder.Code)
		}
		if len(sink.entries) != 1 || sink.entries[0].Action != "log" {
			t.Fatalf("unexpected conservative aggregate entries: %#v", sink.entries)
		}
		decision, ok := sink.entries[0].Metadata["waf_policy_decision"].(webAttackPolicyDecision)
		if !ok {
			t.Fatalf("missing conservative aggregate policy decision: %#v", sink.entries[0].Metadata)
		}
		if decision.Action != engine.ActionLog.String() || decision.RiskScore >= decision.MinimumRiskScore || decision.EvidenceCount != 2 {
			t.Fatalf("unexpected conservative aggregate policy decision: %#v", decision)
		}
	})

	t.Run("aggregate evidence deduplicates analyzer and detector for same payload", func(t *testing.T) {
		analyzer := engine.DetectionResult{
			Detected:   true,
			DetectorID: "semantic.analyzer.sqli",
			Category:   "sqli",
			Severity:   engine.SeverityHigh,
			Action:     engine.ActionBlock,
			Message:    "syntax: boolean predicate; semantics: tautology",
			Confidence: 0.82,
			Payload:    "id=1 or 1=1",
		}
		legacy := analyzer
		legacy.DetectorID = "semantic.sql"
		legacy.Message = "SQL injection pattern matched"
		decision := evaluateWebAttackPolicyWithEvidence(config.ProtectionLevelSmart, &analyzer, []engine.DetectionResult{analyzer, legacy})
		if decision.EvidenceCount != 1 {
			t.Fatalf("expected duplicate analyzer/legacy evidence to count once, got %#v", decision)
		}
		if decision.Action != engine.ActionLog.String() || decision.RiskScore >= decision.MinimumRiskScore {
			t.Fatalf("duplicate evidence should not inflate smart policy to block, got %#v", decision)
		}
	})
}

func TestWebAttackPolicyThresholdsAreMonotonic(t *testing.T) {
	levels := []struct {
		level     string
		paranoia  int
		severity  engine.Severity
		conf      float64
		riskScore int
	}{
		{level: config.ProtectionLevelLow, paranoia: 1, severity: engine.SeverityCritical, conf: 0.90, riskScore: 90},
		{level: config.ProtectionLevelSmart, paranoia: 2, severity: engine.SeverityHigh, conf: 0.85, riskScore: 73},
		{level: config.ProtectionLevelHigh, paranoia: 3, severity: engine.SeverityMedium, conf: 0.78, riskScore: 48},
		{level: config.ProtectionLevelStrict, paranoia: 4, severity: engine.SeverityLow, conf: 0.65, riskScore: 23},
	}

	var previousSeverity engine.Severity
	var previousConfidence float64
	var previousRiskScore int
	for index, tc := range levels {
		severity, confidence := webAttackThreshold(tc.level)
		riskScore := webAttackRiskThreshold(tc.level)
		paranoia := webAttackParanoiaLevel(tc.level)
		if severity != tc.severity || confidence != tc.conf || riskScore != tc.riskScore || paranoia != tc.paranoia {
			t.Fatalf("unexpected threshold for %s: severity=%s confidence=%.2f risk=%d paranoia=%d", tc.level, severity, confidence, riskScore, paranoia)
		}
		if index > 0 {
			if severity > previousSeverity {
				t.Fatalf("level %s should not require higher severity than previous level", tc.level)
			}
			if confidence > previousConfidence {
				t.Fatalf("level %s should not require higher confidence than previous level", tc.level)
			}
			if riskScore > previousRiskScore {
				t.Fatalf("level %s should not require higher aggregate risk than previous level", tc.level)
			}
		}
		previousSeverity = severity
		previousConfidence = confidence
		previousRiskScore = riskScore
	}
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

func TestServerNormalizesPathBeforeBotPolicy(t *testing.T) {
	// /api/../admin must not inherit /api/ exemption after path.Clean → /admin.
	server, sink, cleanup := newBotCCTestServer(t, config.ProtectionLevelSmart, func(cfg *config.Config) {
		cfg.Protection.Bot.Enabled = true
		cfg.Protection.Bot.JSChallenge = true
		cfg.Protection.Bot.PathPrefixes = []string{"/"}
		cfg.Protection.Bot.ExemptPathPrefixes = []string{"/api/", "/health"}
		cfg.Protection.RateLimit.Enabled = false
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/../admin", nil)
	req.Header.Set("User-Agent", "sqlmap")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code == http.StatusOK {
		t.Fatalf("dotdot path under exempt prefix must not pass unchallenged; logs=%#v", sink.entries)
	}
	// Health prefix must not match /healthxyz (segment boundary).
	req = httptest.NewRequest(http.MethodGet, "http://localhost/healthxyz", nil)
	req.Header.Set("User-Agent", "sqlmap")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code == http.StatusOK {
		t.Fatalf("/healthxyz must not be treated as exempt /health; code=%d logs=%#v", recorder.Code, sink.entries)
	}
}

func TestServerRejectsPathWithNUL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/ok", nil)
	req.URL.Path = "/foo\x00bar"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for NUL path, code=%d", recorder.Code)
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
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
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
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
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
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testHMACJWT(t, "proxy-secret", map[string]any{"iss": "issuer-a", "scope": []string{"orders:read"}}))
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
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/orders", nil)
		req.Header.Set("Authorization", "Bearer "+testHMACJWT(t, "proxy-secret", map[string]any{"iss": "issuer-a", "scope": []string{"orders:write"}}))
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
			cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
			cfg.APISec.Auth.JWTSharedSecret = "proxy-secret"
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
	result   *engine.DetectionResult
	priority int
}

func (d staticDetector) ID() string   { return "test.semantic" }
func (d staticDetector) Name() string { return "Test Semantic Detector" }
func (d staticDetector) Priority() int {
	if d.priority != 0 {
		return d.priority
	}
	return 1
}
func (d staticDetector) Detect(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) {
	return d.result, nil
}

func newPolicyTestServer(t *testing.T, level string, result *engine.DetectionResult) (*Server, *captureSink, func()) {
	t.Helper()
	return newPolicyTestServerWithDetectors(t, level, staticDetector{result: result})
}

func newPolicyTestServerWithDetectors(t *testing.T, level string, detectors ...engine.Detector) (*Server, *captureSink, func()) {
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
	server, err := NewServer(&cfg, engine.NewPipeline(detectors...), sink)
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

func TestBotBehaviorVerifyEndpointBypassesWAFAndUpstream(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { upstreamHits++; w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.Bot.Secret = strings.Repeat("s", 48)
	cfg.Protection.IP.Whitelist, cfg.Protection.IP.Blacklist = nil, nil
	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewSQLDetector("block")), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "http://localhost"+botBehaviorVerifyPath+"?q=%27%20OR%201%3D1", nil)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("method %s status=%d allow=%q", method, rec.Code, rec.Header().Get("Allow"))
		}
	}
	req := httptest.NewRequest(http.MethodPost, "http://localhost"+botBehaviorVerifyPath, strings.NewReader(`{"token":"unknown"}`))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token status=%d body=%q", rec.Code, rec.Body.String())
	}
	if upstreamHits != 0 {
		t.Fatalf("verify endpoint reached upstream %d times", upstreamHits)
	}
}

func TestBotBehaviorVerifyEndpointRejectsBodiesOver64KiB(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.Bot.Secret = strings.Repeat("s", 48)
	cfg.Protection.IP.Whitelist, cfg.Protection.IP.Blacklist = nil, nil
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	for _, chunked := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodPost, "http://localhost"+botBehaviorVerifyPath, strings.NewReader(`{"token":"`+strings.Repeat("x", 64<<10)+`"}`))
		if chunked {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v status=%d", chunked, rec.Code)
		}
	}
}

func TestRequestIsHTTPSTrustsForwardedProtoOnlyFromTrustedProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	if requestIsHTTPS(req, nil) {
		t.Fatal("untrusted forwarded proto was accepted")
	}
	if !requestIsHTTPS(req, []string{"192.0.2.0/24"}) {
		t.Fatal("trusted forwarded proto was rejected")
	}
	req.Header.Set("X-Forwarded-Proto", "http")
	if requestIsHTTPS(req, []string{"192.0.2.0/24"}) {
		t.Fatal("forwarded http was treated as secure")
	}
}
