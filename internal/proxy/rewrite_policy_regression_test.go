package proxy

import (
	"bytes"
	"context"
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

func newRewritePolicyTestServer(t *testing.T, from, to string, configure func(*config.Config)) (*Server, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Upstream-URI", r.URL.RequestURI())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Protection.Bot.Enabled = false
	cfg.Protection.Policy.ThreatIntel = config.ProtectionLevelOff
	cfg.Protection.Policy.APISecurity = config.ProtectionLevelSmart
	cfg.APISec.Enabled = true
	cfg.APISec.Auth.Enabled = false
	cfg.APISec.Validation.Enabled = false
	cfg.APISec.RateLimits = nil
	cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: from, Replacement: to}}
	if configure != nil {
		configure(&cfg)
	}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, calls
}

func rewritePolicyRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://localhost"+path, nil)
	req.RemoteAddr = "203.0.113.10:12345"
	return req
}

func TestRewritePreservesAuthenticationOnBothPathsBeforeBodyRead(t *testing.T) {
	for _, tc := range []struct{ name, publicPath, targetPath string }{
		{"public API", "/api/private", "/public"},
		{"upstream API", "/public", "/api/private"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^"+tc.publicPath+"$", tc.targetPath, func(cfg *config.Config) {
				cfg.APISec.Auth.Enabled = true
				cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
				cfg.APISec.Auth.JWTSharedSecret = "rewrite-secret"
			})
			body := &apiSecurityReadTrackingBody{reader: bytes.NewReader([]byte("payload"))}
			req := rewritePolicyRequest(tc.publicPath)
			req.Body, req.ContentLength = body, -1
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("authentication bypassed by rewrite: status=%d body=%q", rec.Code, rec.Body.String())
			}
			if calls.Load() != 0 || body.reads != 0 {
				t.Fatalf("unauthenticated request reached upstream=%d or read body=%d", calls.Load(), body.reads)
			}
		})
	}
}

func TestRewritePreservesIPBlockOnEitherPath(t *testing.T) {
	for _, blockedPath := range []string{"/private", "/public"} {
		t.Run(blockedPath, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/private$", "/public", func(cfg *config.Config) {
				cfg.Protection.IP.Whitelist = []string{"203.0.113.10"}
				cfg.Protection.IP.AccessRules = []config.IPAccessRuleConfig{{
					ID: "path-block", Enabled: true, Action: "block", Scope: "path", PathPrefix: blockedPath, Entries: []string{"203.0.113.10"},
				}}
			})
			body := &apiSecurityReadTrackingBody{reader: bytes.NewReader([]byte("payload"))}
			req := rewritePolicyRequest("/private")
			req.Body, req.ContentLength = body, -1
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || calls.Load() != 0 || body.reads != 0 {
				t.Fatalf("IP path block bypassed by rewrite: status=%d upstream=%d body reads=%d", rec.Code, calls.Load(), body.reads)
			}
		})
	}
}

func TestRewritePathAllowDoesNotExemptOtherPath(t *testing.T) {
	for _, allowedPath := range []string{"/api/private", "/public"} {
		t.Run(allowedPath, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/api/private$", "/public", func(cfg *config.Config) {
				cfg.APISec.Auth.Enabled = true
				cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
				cfg.APISec.Auth.JWTSharedSecret = "rewrite-secret"
				cfg.Protection.IP.AccessRules = []config.IPAccessRuleConfig{{
					ID: "path-allow", Enabled: true, Action: "allow", Scope: "path", PathPrefix: allowedPath, Entries: []string{"203.0.113.10"},
				}}
			})
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, rewritePolicyRequest("/api/private"))
			if rec.Code != http.StatusUnauthorized || calls.Load() != 0 {
				t.Fatalf("one path allow exempted both identities: status=%d upstream=%d", rec.Code, calls.Load())
			}
		})
	}
}

func TestRewriteGlobalAllowStillAppliesToBothPaths(t *testing.T) {
	server, calls := newRewritePolicyTestServer(t, "^/api/private$", "/public", func(cfg *config.Config) {
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
		cfg.APISec.Auth.JWTSharedSecret = "rewrite-secret"
		cfg.Protection.IP.Whitelist = []string{"203.0.113.10"}
	})
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, rewritePolicyRequest("/api/private"))
	if rec.Code != http.StatusNoContent || rec.Header().Get("X-Upstream-URI") != "/public" || calls.Load() != 1 {
		t.Fatalf("global allow or rewritten upstream changed: status=%d uri=%q upstream=%d", rec.Code, rec.Header().Get("X-Upstream-URI"), calls.Load())
	}
}

func TestRewritePreservesEndpointRateLimitOnBothPaths(t *testing.T) {
	for _, limitPath := range []string{"/api/private", "/public"} {
		t.Run(limitPath, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/api/private$", "/public", func(cfg *config.Config) {
				cfg.APISec.RateLimits = []config.APIEndpointLimitConfig{{
					ID: "path-rate", Enabled: true, Method: http.MethodPost, PathPattern: "^" + limitPath + "$", Requests: 1, Window: time.Minute,
				}}
			})
			first := httptest.NewRecorder()
			server.Handler().ServeHTTP(first, rewritePolicyRequest("/api/private"))
			if first.Code != http.StatusNoContent {
				t.Fatalf("initial request status=%d body=%q", first.Code, first.Body.String())
			}
			body := &apiSecurityReadTrackingBody{reader: bytes.NewReader([]byte("payload"))}
			req := rewritePolicyRequest("/api/private")
			req.Body, req.ContentLength = body, -1
			second := httptest.NewRecorder()
			server.Handler().ServeHTTP(second, req)
			if second.Code != http.StatusTooManyRequests || calls.Load() != 1 || body.reads != 0 {
				t.Fatalf("endpoint limit bypassed: status=%d upstream=%d body reads=%d", second.Code, calls.Load(), body.reads)
			}
		})
	}
}

func TestRewriteEndpointRateLimitChargesMatchingRuleOnce(t *testing.T) {
	for _, tc := range []struct{ name, replacement, pattern string }{
		{"both paths", "/public", "^/(api/private|public)$"},
		{"query only", "/api/private?rewritten=1", "^/api/private$"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, calls := newRewritePolicyTestServer(t, "^/api/private$", tc.replacement, func(cfg *config.Config) {
				cfg.APISec.RateLimits = []config.APIEndpointLimitConfig{{
					ID: "shared-rate", Enabled: true, Method: http.MethodPost, PathPattern: tc.pattern, Requests: 2, Window: time.Minute,
				}}
			})
			for n, want := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests} {
				rec := httptest.NewRecorder()
				server.Handler().ServeHTTP(rec, rewritePolicyRequest("/api/private"))
				if rec.Code != want {
					t.Fatalf("request %d status=%d, want %d (shared rule must count once)", n+1, rec.Code, want)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("upstream requests=%d, want 2", calls.Load())
			}
		})
	}
}

func TestRewriteAuthenticationRequiresBothEndpointScopes(t *testing.T) {
	server, calls := newRewritePolicyTestServer(t, "^/api/private$", "/api/upstream", func(cfg *config.Config) {
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
		cfg.APISec.Auth.JWTSharedSecret = "rewrite-secret"
		cfg.APISec.Auth.EndpointPolicies = []config.APIAuthEndpointPolicyConfig{
			{ID: "public", Enabled: true, PathPattern: "^/api/private$", RequiredScopes: []string{"public:read"}},
			{ID: "target", Enabled: true, PathPattern: "^/api/upstream$", RequiredScopes: []string{"upstream:read"}},
		}
	})
	for _, tc := range []struct {
		scope string
		want  int
	}{
		{"public:read", http.StatusForbidden},
		{"upstream:read", http.StatusForbidden},
		{"public:read upstream:read", http.StatusNoContent},
	} {
		req := rewritePolicyRequest("/api/private")
		req.Header.Set("Authorization", "Bearer "+testHMACJWT(t, "rewrite-secret", map[string]any{"scope": tc.scope}))
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("scope %q status=%d, want %d: %s", tc.scope, rec.Code, tc.want, rec.Body.String())
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream requests=%d, want only the token satisfying both endpoints", calls.Load())
	}
}

func TestRewriteBotScopeChecksBothRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name, public, target string
		want                 int
	}{
		{"protected to exempt", "/protected", "/health", http.StatusForbidden},
		{"protected to outside scope", "/protected", "/outside", http.StatusForbidden},
		{"exempt to protected", "/health", "/protected", http.StatusForbidden},
		{"both exempt", "/health", "/health/ready", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
				cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: "^" + tc.public + "$", Replacement: tc.target}}
				cfg.Protection.Bot.PathPrefixes = []string{"/protected"}
				cfg.Protection.Bot.ExemptPathPrefixes = []string{"/health"}
			})
			rec := fixture.request(http.MethodGet, tc.public, "198.51.100.80", bug067068UserAgent, nil)
			if rec.Code != tc.want {
				t.Fatalf("bot scope rewrite status=%d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusForbidden && fixture.upstreamHits.Load() != 0 {
				t.Fatal("bot-protected rewrite reached upstream")
			}
		})
	}
}

func TestRewriteChallengeAndClearanceBindPublicRequest(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: "^/protected/public$", Replacement: "/protected/upstream?upstream=1"}}
		cfg.Protection.Bot.PathPrefixes = []string{"/protected"}
	})
	const public = "/protected/public?original=1"
	issued := fixture.request(http.MethodGet, public, "198.51.100.81", bug067068UserAgent, nil)
	challenge := requireBUG067068PoWChallenge(t, issued)
	form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {solveBUG067068PoW(t, challenge)}}
	wrongPath := fixture.request(http.MethodPost, "/protected/upstream", "198.51.100.81", bug067068UserAgent, form)
	if wrongPath.Code != http.StatusForbidden {
		t.Fatalf("public challenge verified against target identity: status=%d", wrongPath.Code)
	}
	verified := fixture.request(http.MethodPost, public, "198.51.100.81", bug067068UserAgent, form)
	if verified.Code != http.StatusSeeOther || verified.Header().Get("Location") != public {
		t.Fatalf("public verification failed: status=%d location=%q", verified.Code, verified.Header().Get("Location"))
	}
	clearance := bug067068ResponseCookie(verified, bug067068CookieName)
	if clearance == nil || clearance.Value == "" {
		t.Fatal("public challenge did not issue clearance")
	}
	allowed := fixture.request(http.MethodGet, public, "198.51.100.81", bug067068UserAgent, nil, clearance)
	if allowed.Code != http.StatusOK || allowed.Body.String() != "upstream:/protected/upstream?upstream=1" {
		t.Fatalf("public clearance did not reach rewritten origin: status=%d body=%q", allowed.Code, allowed.Body.String())
	}
	if rec := fixture.request(http.MethodGet, "/protected/upstream", "198.51.100.81", bug067068UserAgent, nil, clearance); rec.Code != http.StatusForbidden {
		t.Fatalf("public clearance escaped its path scope: status=%d", rec.Code)
	}
}

func TestRewriteACLChallengeBindsPublicRequest(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: "^/protected/public$", Replacement: "/protected/upstream?upstream=1"}}
		cfg.Protection.Bot.Enabled = false
		cfg.Protection.ACL.Enabled = true
		cfg.Protection.ACL.Rules = []config.ACLRuleConfig{{ID: "challenge", Enabled: true, PathPrefix: "/protected", Action: "challenge"}}
	})
	const public = "/protected/public?original=1"
	issued := fixture.request(http.MethodGet, public, "198.51.100.82", bug067068UserAgent, nil)
	challenge := requireBUG067068PoWChallenge(t, issued)
	form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {solveBUG067068PoW(t, challenge)}}
	verified := fixture.request(http.MethodPost, public, "198.51.100.82", bug067068UserAgent, form)
	if verified.Code != http.StatusSeeOther || verified.Header().Get("Location") != public {
		t.Fatalf("ACL challenge used target identity: status=%d location=%q", verified.Code, verified.Header().Get("Location"))
	}
}

func TestRewriteWaitingRoomAdmitsOnePublicClient(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: "^/protected$", Replacement: "/health"}}
		cfg.Protection.Bot.PathPrefixes = []string{"/protected"}
		cfg.Protection.Bot.WaitingRoom = true
		cfg.Protection.Bot.WaitingRoomMaxActive = 1
	})
	const public = "/protected?original=1"
	admitted := fixture.request(http.MethodGet, public, "198.51.100.83", bug067068UserAgent, nil)
	if admitted.Code != http.StatusTooManyRequests {
		t.Fatalf("waiting room bypassed by rewrite: status=%d", admitted.Code)
	}
	queueCookie := bug067068ResponseCookie(admitted, bug067068CookieName+"_queue")
	if queueCookie == nil || len(admitted.Result().Cookies()) != 1 {
		t.Fatalf("waiting room issued %d cookies, want one admission", len(admitted.Result().Cookies()))
	}
	issued := fixture.request(http.MethodGet, public, "198.51.100.83", bug067068UserAgent, nil, queueCookie)
	_ = requireBUG067068PoWChallenge(t, issued)
	if bug067068ResponseCookie(issued, bug067068CookieName+"_queue") != nil {
		t.Fatal("admitted client received a second waiting-room admission")
	}
	other := fixture.request(http.MethodGet, public, "198.51.100.84", bug067068UserAgent, nil)
	if other.Code != http.StatusTooManyRequests || other.Header().Get("Retry-After") == "" || bug067068ResponseCookie(other, bug067068CookieName+"_queue") != nil {
		t.Fatalf("waiting room capacity was not retained: status=%d cookies=%v", other.Code, other.Result().Cookies())
	}
}

type rewriteChallengeBody struct {
	reader *strings.Reader
	read   int
}

func (b *rewriteChallengeBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (*rewriteChallengeBody) Close() error { return nil }

func TestRewritePublicChallengeRetainsBodyLimit(t *testing.T) {
	fixture := newBUG067068ProxyFixture(t, func(cfg *config.Config) {
		cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "route", Enabled: true, Pattern: "^/protected$", Replacement: "/protected/target"}}
		cfg.Sites[0].WAF.Performance.MaxBodyBytes = 128
	})
	body := &rewriteChallengeBody{reader: strings.NewReader("cw_pow_token=" + strings.Repeat("x", 1<<20))}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/protected", nil)
	req.RemoteAddr = "198.51.100.85:43210"
	req.Header.Set("User-Agent", bug067068UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body, req.ContentLength = body, -1
	rec := httptest.NewRecorder()
	fixture.handler.ServeHTTP(rec, req)
	if body.read > 129 {
		t.Fatalf("public challenge read %d bytes, bypassing the 128-byte site limit", body.read)
	}
	if fixture.upstreamHits.Load() != 0 {
		t.Fatal("oversized challenge body reached upstream")
	}
}

type rewriteChallengePipeline struct{}

func (rewriteChallengePipeline) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if err := reqCtx.EnsureBody(); err != nil {
		return nil, err
	}
	return &engine.DetectionResult{Detected: true, Category: "detection_incomplete", Action: engine.ActionChallenge, Message: "verification required"}, nil
}

func TestRewritePipelineChallengeUsesReplayedPublicBody(t *testing.T) {
	server, calls := newRewritePolicyTestServer(t, "^/protected/public$", "/protected/upstream", func(cfg *config.Config) {
		cfg.Sites[0].WAF.Enabled = true
		cfg.Sites[0].WAF.Mode = "block"
		cfg.Protection.Policy.WebAttack = config.ProtectionLevelStrict
		cfg.Protection.Bot = config.BotProtectionConfig{
			JSChallenge: true, Secret: strings.Repeat("s", 48), CookieName: bug067068CookieName,
			ChallengeDifficulty: 1, PoWMaxDifficulty: 1,
		}
	})
	server.pipeline = rewriteChallengePipeline{}
	issue := rewritePolicyRequest("/protected/public?original=1")
	issue.Method = http.MethodGet
	issue.Header.Set("User-Agent", bug067068UserAgent)
	issued := httptest.NewRecorder()
	server.Handler().ServeHTTP(issued, issue)
	challenge := requireBUG067068PoWChallenge(t, issued)
	form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {solveBUG067068PoW(t, challenge)}}
	post := rewritePolicyRequest("/protected/public?original=1")
	post.Header.Set("User-Agent", bug067068UserAgent)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Body = &rewriteChallengeBody{reader: strings.NewReader(form.Encode())}
	post.ContentLength = -1
	verified := httptest.NewRecorder()
	server.Handler().ServeHTTP(verified, post)
	if verified.Code != http.StatusSeeOther || verified.Header().Get("Location") != "/protected/public?original=1" {
		t.Fatalf("challenge lost the public body replay: status=%d location=%q", verified.Code, verified.Header().Get("Location"))
	}
	if calls.Load() != 0 {
		t.Fatalf("pipeline challenge reached upstream %d times", calls.Load())
	}
}

type websocketPolicyPipeline struct{ inspected chan struct{} }

func (p websocketPolicyPipeline) Detect(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) {
	if p.inspected != nil {
		close(p.inspected)
	}
	return &engine.DetectionResult{Detected: true, Severity: engine.SeverityCritical, Confidence: 1, Action: engine.ActionBlock, Category: "sqli", Message: "blocked payload"}, nil
}

func TestWebSocketPolicyReadWaitsForRuntimeWriter(t *testing.T) {
	cfg := reviewProxyConfig("http://127.0.0.1:1")
	cfg.Protection.Policy.WebAttack = config.ProtectionLevelStrict
	cfg.Sites[0].WAF.Mode = "block"
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	inspected := make(chan struct{})
	server.pipeline = websocketPolicyPipeline{inspected: inspected}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/socket", nil)
	parent := &engine.RequestContext{SiteID: cfg.Sites[0].ID, ClientIP: "203.0.113.10"}
	server.runtimeMu.Lock()
	done := make(chan error, 1)
	go func() { done <- server.inspectWebSocketMessage(req, cfg.Sites[0], parent, true, 1, []byte("payload")) }()
	select {
	case <-inspected:
	case <-time.After(5 * time.Second):
		server.runtimeMu.Unlock()
		t.Fatal("message inspection was blocked by the runtime writer")
	}
	select {
	case err := <-done:
		server.runtimeMu.Unlock()
		t.Fatalf("WebSocket policy was read while runtime writer held its lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	server.runtimeMu.Unlock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("strict WebSocket policy did not reject detected payload")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message inspection did not finish after runtime writer released lock")
	}
}

func TestWebSocketMessageInspectionConcurrentProtectionUpdates(t *testing.T) {
	cfg := reviewProxyConfig("http://127.0.0.1:1")
	cfg.Protection.Policy.WebAttack = config.ProtectionLevelStrict
	cfg.Sites[0].WAF.Mode = "block"
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.pipeline = websocketPolicyPipeline{}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/socket", nil)
	parent := &engine.RequestContext{SiteID: cfg.Sites[0].ID, ClientIP: "203.0.113.10"}
	start := make(chan struct{})
	updated := make(chan error, 1)
	go func() {
		<-start
		protection := cfg.Protection
		for n := 0; n < 1000; n++ {
			protection.Policy.WebAttack = config.ProtectionLevelStrict
			if n%2 == 0 {
				protection.Policy.WebAttack = config.ProtectionLevelHigh
			}
			if err := server.UpdateProtection(protection); err != nil {
				updated <- err
				return
			}
		}
		updated <- nil
	}()
	close(start)
	for n := 0; n < 1000; n++ {
		if err := server.inspectWebSocketMessage(req, cfg.Sites[0], parent, true, 1, []byte("payload")); err == nil {
			t.Errorf("message %d escaped both strict and high protection policies", n)
			break
		}
	}
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
}

type waitingWebSocketPipeline struct {
	started chan struct{}
	release chan struct{}
}

func (p waitingWebSocketPipeline) Detect(context.Context, *engine.RequestContext) (*engine.DetectionResult, error) {
	close(p.started)
	<-p.release
	return nil, nil
}

func TestWebSocketMessagePipelineDoesNotHoldRuntimeLock(t *testing.T) {
	cfg := reviewProxyConfig("http://127.0.0.1:1")
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	started, release := make(chan struct{}), make(chan struct{})
	server.pipeline = waitingWebSocketPipeline{started: started, release: release}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/socket", nil)
	parent := &engine.RequestContext{SiteID: cfg.Sites[0].ID, ClientIP: "203.0.113.10"}
	done := make(chan error, 1)
	go func() { done <- server.inspectWebSocketMessage(req, cfg.Sites[0], parent, true, 1, []byte("payload")) }()
	<-started
	updated := make(chan error, 1)
	go func() { updated <- server.UpdateProtection(cfg.Protection) }()
	select {
	case err := <-updated:
		close(release)
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		<-done
		t.Fatal("slow WebSocket message inspection blocked a protection update")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
