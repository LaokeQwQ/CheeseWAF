package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func reviewProxyConfig(address string) config.Config {
	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: address}}
	cfg.Protection.Policy.BotCC = config.ProtectionLevelOff
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	cfg.Protection.RateLimit.Enabled = false
	cfg.Edge.Cache.Enabled = false
	cfg.Edge.Compression.Enabled = false
	return cfg
}

func TestReviewRewriteTargetPassesPathACL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "private", Enabled: true, Pattern: "^/public$", Replacement: "/admin"}}
	cfg.Protection.ACL.Enabled = true
	cfg.Protection.ACL.Rules = []config.ACLRuleConfig{{ID: "private", Enabled: true, PathPrefix: "/admin", Action: "block"}}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "http://localhost/public", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rewrite escaped ACL: %d %q", rec.Code, rec.Body.String())
	}
}

func TestReviewWebSocketOrdinaryResponseStillInspected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "PRIVATE-REVIEW-SECRET")
	}))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Sites[0].WAF.WebSocketEnabled = true
	cfg.Sites[0].WAF.Mode = "block"
	cfg.Sites[0].WAF.Response.Enabled = true
	cfg.Sites[0].WAF.Response.SensitivePatterns = []string{"PRIVATE-REVIEW-SECRET"}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "PRIVATE-REVIEW-SECRET") {
		t.Fatalf("ordinary response bypassed inspection: %d %q", rec.Code, rec.Body.String())
	}
}

type trailerPublishingBody struct {
	request *http.Request
	sent    bool
}

func (b *trailerPublishingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "safe"), nil
	}
	b.request.Trailer = http.Header{"X-Attack": {"payload"}}
	return 0, io.EOF
}
func (*trailerPublishingBody) Close() error { return nil }

func TestReviewRejectsUndeclaredTrailersAfterBodyRead(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	req := httptest.NewRequest("POST", "http://localhost/", nil)
	req.ContentLength = -1
	req.Body = &trailerPublishingBody{request: req}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("undeclared trailer forwarded: %d %q", rec.Code, rec.Body.String())
	}
}

func TestReviewGRPCRequiresExplicitOptIn(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := reviewProxyConfig(upstream.URL)
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	req := httptest.NewRequest(http.MethodPost, "http://localhost/rpc", strings.NewReader("\x00\x00\x00\x00\x00"))
	req.Header.Set("Content-Type", "application/grpc")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType || hits.Load() != 0 {
		t.Fatalf("gRPC without explicit opt-in passed: status=%d origin hits=%d", rec.Code, hits.Load())
	}
	if !strings.Contains(rec.Body.String(), "message inspection is unavailable") {
		t.Fatalf("missing gRPC capability boundary: %q", rec.Body.String())
	}
}

func TestReviewGRPCResponseTrailersKeepStatusAndDropUnknown(t *testing.T) {
	ctx := &engine.RequestContext{Metadata: map[string]any{}}
	resp := &http.Response{
		Header: http.Header{"Trailer": []string{"Grpc-Status, Grpc-Message, X-Attack"}},
		Trailer: http.Header{
			"Grpc-Status":  []string{"0"},
			"Grpc-Message": []string{"ok"},
			"X-Attack":     []string{"<script>alert(1)</script>"},
		},
		Body: io.NopCloser(strings.NewReader("grpc body")),
	}
	prepareUpstreamResponseTrailers(resp, true, ctx)
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("grpc-status trailer = %q, want 0", got)
	}
	if got := resp.Trailer.Get("X-Attack"); got != "" {
		t.Fatalf("unsafe response trailer survived: %q", got)
	}
	if got := resp.Header.Get("Trailer"); got != "Grpc-Message, Grpc-Status" {
		t.Fatalf("trailer declaration = %q, want standard gRPC trailers only", got)
	}
	if got := ctx.Metadata["grpc_status"]; got != "0" {
		t.Fatalf("grpc status was not recorded: %#v", got)
	}
	dropped, ok := ctx.Metadata["upstream_trailers_dropped"].([]string)
	if !ok || len(dropped) != 1 || dropped[0] != "X-Attack" {
		t.Fatalf("dropped trailer metadata = %#v", ctx.Metadata["upstream_trailers_dropped"])
	}
}

func TestReviewNonGRPCResponseTrailersAreRemoved(t *testing.T) {
	ctx := &engine.RequestContext{Metadata: map[string]any{}}
	resp := &http.Response{
		Header:  http.Header{"Trailer": []string{"X-Attack"}},
		Trailer: http.Header{"X-Attack": []string{"payload"}},
	}
	sanitizeResponseTrailerState(resp, false, ctx)
	if len(resp.Trailer) != 0 || resp.Header.Get("Trailer") != "" {
		t.Fatalf("non-gRPC trailers were not removed: header=%#v trailer=%#v", resp.Header, resp.Trailer)
	}
}

func TestReviewForwardingIdentitySurvivesConnectionTokens(t *testing.T) {
	var received http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = r.Header.Clone(); w.WriteHeader(204) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	rp := NewReverseProxyForClient(target, time.Second, "203.0.113.4")
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Connection", "X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host")
	req.Header.Set("X_Forwarded_For", "evil")
	req.Header.Set("X_Original_Url", "/admin")
	rp.ServeHTTP(httptest.NewRecorder(), req)
	if received.Get("X-Forwarded-For") != "203.0.113.4" || received.Get("X-Real-IP") != "203.0.113.4" || received.Get("X-Forwarded-Proto") != "http" || received.Get("X-Forwarded-Host") != "localhost" {
		t.Fatalf("identity changed: %#v", received)
	}
	if received.Get("X_Forwarded_For") != "" || received.Get("X_Original_Url") != "" {
		t.Fatalf("ambiguous alias forwarded: %#v", received)
	}
}

func TestReviewHealthObservationsStayWithinSite(t *testing.T) {
	a := config.SiteConfig{ID: "a", Upstreams: []config.UpstreamConfig{{Address: "http://shared.test"}}}
	b := a
	b.ID = "b"
	registry := NewHealthRegistry([]config.SiteConfig{a, b})
	server := &Server{health: registry}
	u, _ := url.Parse("http://shared.test")
	server.markUpstreamForSite("a", u, false)
	if registry.HealthyForSite("a", u.String()) || !registry.HealthyForSite("b", u.String()) {
		t.Fatal("request observation crossed site health profiles")
	}
}

func TestReviewHealthChecksRunConcurrentlyAndCancel(t *testing.T) {
	entered := make(chan struct{}, 2)
	checker := NewHealthChecker(nil, NewHealthRegistry(nil))
	checker.client.Transport = healthCheckRoundTripper(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	site := config.SiteConfig{ID: "a", Upstreams: []config.UpstreamConfig{{Address: "http://one.test"}, {Address: "http://two.test"}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { checker.checkContext(ctx, site); close(done) }()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("upstreams checked serially")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled checks kept running")
	}
}
