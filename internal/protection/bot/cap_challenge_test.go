package bot

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

var capFieldPattern = regexp.MustCompile(`name="(cw_cap_[a-z_]+)" value="([^"]*)"`)

func TestCapBotNativeFallbackPreservesVerifiedOriginalMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			p, _ := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"success":false}`))
			}, "pow", func(cfg *config.BotProtectionConfig) { cfg.CAPTCHAEscalationTypes = []string{"pow"} })
			// Keep real native issuance and verification, with a cheap test puzzle.
			p.issueBehaviorChallenge = func(opts captcha.BehaviorOptions) (captcha.BehaviorChallenge, error) {
				opts.Intensity = 1
				return captcha.IssueBehaviorChallenge(opts)
			}
			const ip, site, ua = "203.0.113.95", "site-a", "Mozilla/5.0"
			_, fields := capChallengePage(t, p, method, "https://site-a/private?return=1", ip, site, ua)
			values := url.Values{
				"cw_cap_challenge_id": {fields.ChallengeID}, "cw_cap_context": {fields.Context},
				"cw_cap_method": {fields.Method}, "cw_cap_token": {"provider-rejected-token"},
			}
			req := httptest.NewRequest(http.MethodPost, "https://site-a/private?return=1", strings.NewReader(values.Encode()))
			req.Host = site
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			p.ServeChallengeForSite(rec, req, ip, site)
			state, ownerCookie := capFallbackBehaviorState(t, p, rec, method)
			if state.ReturnURL != "/private?return=1" || strings.Contains(state.ReturnURL, "cw_cap_") {
				t.Fatalf("native fallback changed the safe return URL: %q", state.ReturnURL)
			}
			if req.Method != http.MethodPost || req.PostForm.Get("cw_cap_method") != method {
				t.Fatalf("fallback mutated submitted request: method=%q form=%v", req.Method, req.PostForm)
			}
			proof, solved := captcha.SolveBehaviorPOW(state.Challenge.Presentation.POWSalt, state.Challenge.Presentation.POWDifficulty, 1<<24)
			if !solved {
				t.Fatal("could not solve the real native fallback puzzle")
			}
			verified := verifyBehavior(t, p, captcha.BehaviorResponse{Token: state.Challenge.Token, Proof: proof}, ip, site, ua, ownerCookie)
			if verified.Code != http.StatusOK || len(verified.Result().Cookies()) == 0 {
				t.Fatalf("native fallback verification failed: status=%d body=%s", verified.Code, verified.Body.String())
			}
			clearance := verified.Result().Cookies()[0]
			for _, candidate := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
				request := httptest.NewRequest(candidate, "https://site-a/private", nil)
				request.Host = site
				request.Header.Set("User-Agent", ua)
				request.AddCookie(clearance)
				if got, want := p.hasClearanceForSite(request, ip, site), candidate == method; got != want {
					t.Errorf("original=%s candidate=%s clearance=%v want=%v", method, candidate, got, want)
				}
			}
			request := httptest.NewRequest(method, "https://site-a/private", nil)
			request.Host = site
			request.Header.Set("User-Agent", ua)
			request.AddCookie(clearance)
			if result := p.EvaluateForSite(request, ip, site); result != nil {
				t.Fatalf("original method was challenged after native success: %+v", result)
			}
		})
	}
}

func TestCapBotNativeFallbackDoesNotTrustReplayedMethod(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}, "pow", func(cfg *config.BotProtectionConfig) { cfg.CAPTCHAEscalationTypes = []string{"pow"} })
	const ip, site, ua = "203.0.113.96", "site-a", "Mozilla/5.0"
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	first := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	capFallbackBehaviorState(t, p, first, http.MethodGet)
	for _, forged := range []capChallengeFields{fields, {ChallengeID: fields.ChallengeID, Context: "invalid", Method: http.MethodPut}} {
		replay := postCapAnswer(p, "https://site-a/private", ip, site, ua, forged)
		capFallbackBehaviorState(t, p, replay, http.MethodPost)
	}
	if calls.Load() != 1 {
		t.Fatalf("replayed method reached Cap: calls=%d", calls.Load())
	}
}

func capFallbackBehaviorState(t *testing.T, p *Policy, response *httptest.ResponseRecorder, wantMethod string) (behaviorPageTestState, *http.Cookie) {
	t.Helper()
	if response.Code != http.StatusForbidden {
		t.Fatalf("native fallback status=%d body=%s", response.Code, response.Body.String())
	}
	match := behaviorStatePattern.FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatal("native fallback state missing")
	}
	var state behaviorPageTestState
	if err := json.Unmarshal([]byte(match[1]), &state); err != nil {
		t.Fatal(err)
	}
	p.behaviorPending.mu.Lock()
	pending, exists := p.behaviorPending.entries[behaviorTokenJTI(state.Challenge.Token)]
	p.behaviorPending.mu.Unlock()
	if !exists || pending.pending.method != wantMethod {
		t.Fatalf("native fallback pending method=%q exists=%v want=%q", pending.pending.method, exists, wantMethod)
	}
	if state.Idempotent != (wantMethod == http.MethodGet || wantMethod == http.MethodHead) {
		t.Fatalf("native page idempotence does not match original method %s: %+v", wantMethod, state)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == p.cookieName+behaviorOwnerCookieSuffix {
			return state, cookie
		}
	}
	t.Fatal("native owner cookie missing")
	return state, nil
}

func TestCapBotVerificationBoundsTrustedPeerAndKeepsProofSingleUse(t *testing.T) {
	const capacity = 4
	entered := make(chan struct{}, capacity+1)
	release := make(chan struct{})
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write([]byte(`{"success":true}`))
		case <-r.Context().Done():
		}
	}, "pow")
	var pending sync.WaitGroup
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }); pending.Wait() }
	defer finish()
	const ip, site = "203.0.113.82", "site-a"
	fields := make([]capChallengeFields, capacity+1)
	for i := range fields {
		_, fields[i] = capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, fmt.Sprintf("browser-%d", i))
	}
	for i, proof := range fields[:capacity] {
		pending.Add(1)
		go func() {
			defer pending.Done()
			postCapAnswer(p, "https://site-a/private", ip, site, fmt.Sprintf("browser-%d", i), proof)
		}()
	}
	for i := 0; i < capacity; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("admitted Bot verification did not reach provider")
		}
	}
	busy := postCapAnswer(p, "https://site-a/private", ip, site, fmt.Sprintf("browser-%d", capacity), fields[capacity])
	if busy.Code != http.StatusServiceUnavailable || calls.Load() != capacity || len(busy.Result().Cookies()) != 0 {
		t.Fatalf("peer limit failed closed incorrectly: status=%d provider calls=%d cookies=%v", busy.Code, calls.Load(), busy.Result().Cookies())
	}
	if got := p.failureTracker.Check(p.failureKey(ip, site)); got.Failures != 0 {
		t.Fatalf("busy verification counted as an incorrect answer: %+v", got)
	}
	finish()
	replay := postCapAnswer(p, "https://site-a/private", ip, site, fmt.Sprintf("browser-%d", capacity), fields[capacity])
	if replay.Code != http.StatusForbidden || calls.Load() != capacity || len(replay.Result().Cookies()) != 0 {
		t.Fatalf("busy proof became reusable: status=%d provider calls=%d", replay.Code, calls.Load())
	}
	_, fresh := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, "fresh-browser")
	next := postCapAnswer(p, "https://site-a/private", ip, site, "fresh-browser", fresh)
	if next.Code != http.StatusSeeOther || calls.Load() != capacity+1 {
		t.Fatalf("completed verification retained capacity: status=%d provider calls=%d", next.Code, calls.Load())
	}
}

type capChallengeFields struct {
	ChallengeID string
	Context     string
	Method      string
}

func newCapBotPolicy(t *testing.T, verify http.HandlerFunc, challengeType string, configure ...func(*config.BotProtectionConfig)) (*Policy, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/siteverify" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if verify != nil {
			verify(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(server.Close)

	secretFile := filepath.Join(t.TempDir(), "cap-secret")
	if err := os.WriteFile(secretFile, []byte("test-cap-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Protection.Bot
	cfg.Enabled = true
	cfg.CAPTCHA = true
	cfg.CAPTCHAType = challengeType
	cfg.CAPTCHATypes = []string{challengeType}
	cfg.CAPTCHAEscalationTypes = []string{"pow", "shape_slider"}
	cfg.CAPTCHAMaxAttempts = 3
	cfg.CAPTCHAProvider = "cap"
	cfg.Secret = strings.Repeat("s", 48)
	cfg.CookieName = "cw_clearance"
	cfg.ChallengeTTL = 10 * time.Minute
	cfg.CAPTCHAChallengeTTL = 2 * time.Minute
	cfg.CAPTCHAPolicyVersion = "cap-test-v1"
	cfg.ClearanceMethodScope = true
	for _, change := range configure {
		change(&cfg)
	}
	providers := config.CAPTCHAProvidersConfig{Cap: config.CapStandaloneConfig{
		APIEndpoint: server.URL,
		WidgetURL:   server.URL + "/assets/cap.js",
		WASMURL:     server.URL + "/assets/cap.wasm",
		HashWXURL:   server.URL + "/assets/hash-wx.js",
		SecretFile:  secretFile,
		Timeout:     time.Second,
	}}
	policy, err := NewPolicyWithCAPTCHAProviders(cfg, providers, nil)
	if err != nil {
		t.Fatalf("construct Cap policy: %v", err)
	}
	return policy, &calls
}

func TestCapBotRejectedAnswersEscalateForBoundSite(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}, "pow")
	const ip, site, ua = "203.0.113.91", "bound-site", "Mozilla/5.0"
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	answer := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	decision := p.failureTracker.Check(p.failureKey(ip, site))
	if calls.Load() != 1 || decision.Failures != 1 || decision.Level != 1 {
		t.Fatalf("rejected Cap answer did not update bound failure budget: calls=%d decision=%+v", calls.Load(), decision)
	}
	if answer.Code != http.StatusForbidden || !strings.Contains(answer.Body.String(), `id="stage"`) || strings.Contains(answer.Body.String(), "<cap-widget") {
		t.Fatalf("Cap failure did not upgrade to configured native challenge: status=%d body=%q", answer.Code, answer.Body.String())
	}
	if got := p.failureTracker.Check(p.failureKey(ip, "site-a")); got.Failures != 0 {
		t.Fatalf("Cap failure was attributed to transport host instead of bound site: %+v", got)
	}
}

func TestCapBotRejectedAnswersEventuallyBlock(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}, "pow", func(cfg *config.BotProtectionConfig) { cfg.CAPTCHAEscalationTypes = nil })
	const ip, site, ua = "203.0.113.92", "site-a", "Mozilla/5.0"
	for attempt := 1; attempt <= p.captchaMaxAttempts; attempt++ {
		_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
		answer := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
		decision := p.failureTracker.Check(p.failureKey(ip, site))
		if decision.Failures != attempt {
			t.Fatalf("attempt %d failure count=%d", attempt, decision.Failures)
		}
		wantStatus := http.StatusForbidden
		if attempt == p.captchaMaxAttempts {
			wantStatus = http.StatusTooManyRequests
			if !decision.Blocked {
				t.Fatalf("configured failure threshold did not block: %+v", decision)
			}
		}
		if answer.Code != wantStatus || len(answer.Result().Cookies()) != 0 {
			t.Fatalf("attempt %d status=%d cookies=%v want=%d", attempt, answer.Code, answer.Result().Cookies(), wantStatus)
		}
	}
	if calls.Load() != int32(p.captchaMaxAttempts) {
		t.Fatalf("remote verification count=%d", calls.Load())
	}
	request := httptest.NewRequest(http.MethodGet, "https://site-a/private", nil)
	request.Header.Set("User-Agent", ua)
	if got := p.EvaluateForSite(request, ip, site); got == nil || got.DetectorID != "bot.failure" {
		t.Fatalf("failed Cap answers did not enforce the existing block: %+v", got)
	}
}

func TestCapBotSuccessfulAnswerResetsFailureBudget(t *testing.T) {
	var accept atomic.Bool
	p, _ := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"success":%t}`, accept.Load())
	}, "pow", func(cfg *config.BotProtectionConfig) { cfg.CAPTCHAEscalationTypes = nil })
	const ip, site, ua = "203.0.113.93", "bound-site", "Mozilla/5.0"
	_, rejected := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	postCapAnswer(p, "https://site-a/private", ip, site, ua, rejected)
	if got := p.failureTracker.Check(p.failureKey(ip, site)); got.Failures != 1 {
		t.Fatalf("initial failure was not recorded: %+v", got)
	}
	accept.Store(true)
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	answer := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	if answer.Code != http.StatusSeeOther || len(answer.Result().Cookies()) != 1 {
		t.Fatalf("successful answer did not issue native clearance: status=%d cookies=%v", answer.Code, answer.Result().Cookies())
	}
	if got := p.failureTracker.Check(p.failureKey(ip, site)); got.Failures != 0 || got.Level != 0 || got.Blocked {
		t.Fatalf("successful Cap answer did not reset the existing failure budget: %+v", got)
	}
}

func TestCapBotRejectedProofReplayDoesNotCountAgain(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false}`))
	}, "pow", func(cfg *config.BotProtectionConfig) { cfg.CAPTCHAEscalationTypes = nil })
	const ip, site, ua = "203.0.113.94", "site-a", "Mozilla/5.0"
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	for range 2 {
		postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	}
	if got := p.failureTracker.Check(p.failureKey(ip, site)); got.Failures != 1 || calls.Load() != 1 {
		t.Fatalf("replayed proof changed failure budget: decision=%+v provider calls=%d", got, calls.Load())
	}
}

func capChallengePage(t *testing.T, p *Policy, method, target, ip, site, ua string) (*httptest.ResponseRecorder, capChallengeFields) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = site
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	p.ServeChallengeForSite(rec, req, ip, site)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("challenge status=%d body=%q", rec.Code, rec.Body.String())
	}
	fields := capChallengeFields{}
	for _, match := range capFieldPattern.FindAllStringSubmatch(rec.Body.String(), -1) {
		switch match[1] {
		case "cw_cap_challenge_id":
			fields.ChallengeID = match[2]
		case "cw_cap_context":
			fields.Context = match[2]
		case "cw_cap_method":
			fields.Method = match[2]
		}
	}
	if fields.ChallengeID == "" || fields.Context == "" || fields.Method == "" {
		t.Fatalf("Cap challenge fields missing: %+v", fields)
	}
	return rec, fields
}

func postCapAnswer(p *Policy, target, ip, site, ua string, fields capChallengeFields) *httptest.ResponseRecorder {
	values := url.Values{
		"cw_cap_challenge_id": {fields.ChallengeID},
		"cw_cap_context":      {fields.Context},
		"cw_cap_method":       {fields.Method},
		"cw_cap_token":        {"cap-valid-token"},
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Host = site
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.ServeChallengeForSite(rec, req, ip, site)
	return rec
}

func TestCapBotClassicChallengeUsesWidgetAndLocalClearance(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Secret   string `json:"secret"`
			Response string `json:"response"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode siteverify body: %v", err)
		}
		if payload.Secret != "test-cap-secret" || payload.Response != "cap-valid-token" {
			t.Errorf("unexpected siteverify payload: secret=%q response=%q", payload.Secret, payload.Response)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}, "pow")
	const ip, site, ua = "203.0.113.8", "site-a", "browser-a"
	page, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private?return=1", ip, site, ua)
	if !strings.Contains(page.Body.String(), "<cap-widget") || !strings.Contains(page.Body.String(), "cap.js") || strings.Contains(page.Body.String(), "cw_pow_token") {
		t.Fatalf("classic challenge is not Cap-backed: %q", page.Body.String())
	}
	csp := page.Header().Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "http://127.0.0.1", "script-src", "connect-src"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q missing %q", csp, want)
		}
	}
	if page.Header().Get("Cache-Control") != "no-store" || len(page.Result().Cookies()) != 0 {
		t.Fatalf("challenge caching/cookie behavior unexpected: headers=%v cookies=%v", page.Header(), page.Result().Cookies())
	}

	result := postCapAnswer(p, "https://site-a/private?return=1", ip, site, ua, fields)
	if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/private?return=1" {
		t.Fatalf("valid Cap answer status=%d location=%q body=%q", result.Code, result.Header().Get("Location"), result.Body.String())
	}
	cookies := result.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "cw_clearance" || !cookies[0].HttpOnly || cookies[0].Value == "" {
		t.Fatalf("CheeseWAF clearance cookie missing or malformed: %+v", cookies)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("siteverify calls=%d, want 1", got)
	}
	allowed := httptest.NewRequest(http.MethodGet, "https://site-a/private?return=1", nil)
	allowed.Host = site
	allowed.Header.Set("User-Agent", ua)
	allowed.AddCookie(cookies[0])
	if decision := p.EvaluateForSite(allowed, ip, site); decision != nil {
		t.Fatalf("native clearance rejected protected request: %+v", decision)
	}
	if replay := postCapAnswer(p, "https://site-a/private?return=1", ip, site, ua, fields); replay.Code != http.StatusForbidden {
		t.Fatalf("replayed Cap challenge status=%d body=%q", replay.Code, replay.Body.String())
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("replay reached siteverify: calls=%d", got)
	}
}

func TestCapBotPostClearanceAllows303GetButNotOtherMethods(t *testing.T) {
	p, _ := newCapBotPolicy(t, nil, "pow")
	const ip, site, ua = "203.0.113.88", "site-a", "browser-a"
	_, fields := capChallengePage(t, p, http.MethodPost, "https://site-a/orders?ignored=1", ip, site, ua)
	if fields.Method != http.MethodPost {
		t.Fatalf("challenge did not retain original method: %q", fields.Method)
	}
	result := postCapAnswer(p, "https://site-a/orders", ip, site, ua, fields)
	if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/orders" {
		t.Fatalf("POST redemption status=%d location=%q body=%q", result.Code, result.Header().Get("Location"), result.Body.String())
	}
	cookies := result.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("clearance cookie missing: %v", cookies)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "https://site-a/orders", nil)
		req.Host = site
		req.Header.Set("User-Agent", ua)
		req.AddCookie(cookies[0])
		if !p.hasClearanceForSite(req, ip, site) {
			t.Errorf("clearance rejected %s at the exact protected path", method)
		}
	}
	for _, tc := range []struct{ method, target string }{
		{http.MethodPut, "https://site-a/orders"},
		{http.MethodGet, "https://site-a/other"},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		req.Host = site
		req.Header.Set("User-Agent", ua)
		req.AddCookie(cookies[0])
		if p.hasClearanceForSite(req, ip, site) {
			t.Errorf("clearance accepted unrelated request %s %s", tc.method, tc.target)
		}
	}
}

func TestCapBotChallengeBindingRejectsOtherIPUAPathAndReceipt(t *testing.T) {
	p, calls := newCapBotPolicy(t, nil, "pow")
	const ip, site, ua = "203.0.113.18", "site-a", "browser-a"
	cases := []struct {
		name   string
		target string
		ip     string
		site   string
		ua     string
		mutate func(*capChallengeFields)
	}{
		{name: "ip", target: "https://site-a/private", ip: "198.51.100.2", site: site, ua: ua},
		{name: "user agent", target: "https://site-a/private", ip: ip, site: site, ua: "browser-b"},
		{name: "path", target: "https://site-a/other", ip: ip, site: site, ua: ua},
		{name: "receipt", target: "https://site-a/private", ip: ip, site: site, ua: ua, mutate: func(f *capChallengeFields) { f.Context += "x" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
			if tc.mutate != nil {
				tc.mutate(&fields)
			}
			bad := postCapAnswer(p, tc.target, tc.ip, tc.site, tc.ua, fields)
			if bad.Code != http.StatusForbidden || calls.Load() != 0 {
				t.Fatalf("binding violation was accepted or sent to siteverify: status=%d calls=%d", bad.Code, calls.Load())
			}
		})
	}
}

func TestCapBotSiteVerifyErrorFailsClosed(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream failure", http.StatusBadGateway)
	}, "pow")
	const ip, site, ua = "203.0.113.28", "site-a", "browser-a"
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	result := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	if result.Code != http.StatusServiceUnavailable || len(result.Result().Cookies()) != 0 {
		t.Fatalf("siteverify error did not fail closed: status=%d cookies=%v body=%q", result.Code, result.Result().Cookies(), result.Body.String())
	}
	if strings.Contains(result.Body.String(), "test-cap-secret") || calls.Load() != 1 {
		t.Fatalf("siteverify failure leaked secret or was not called once: calls=%d body=%q", calls.Load(), result.Body.String())
	}
	if got := p.failureTracker.Check(p.failureKey(ip, site)); got.Failures != 0 {
		t.Fatalf("provider failure counted as an incorrect answer: %+v", got)
	}
}

func TestCapBotSiteVerifyFalseDoesNotIssueClearance(t *testing.T) {
	p, calls := newCapBotPolicy(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false}`))
	}, "pow")
	const ip, site, ua = "203.0.113.29", "site-a", "browser-a"
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	result := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	if result.Code != http.StatusForbidden || !strings.Contains(result.Body.String(), `id="stage"`) || strings.Contains(result.Body.String(), "<cap-widget") {
		t.Fatalf("negative siteverify result did not upgrade the challenge: status=%d cookies=%v", result.Code, result.Result().Cookies())
	}
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == p.cookieName {
			t.Fatalf("negative siteverify result issued clearance: %+v", cookie)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("siteverify calls=%d, want 1", calls.Load())
	}
}

func TestCapBotEscalationRejectsPendingCapAnswer(t *testing.T) {
	p, calls := newCapBotPolicy(t, nil, "pow")
	const ip, site, ua = "203.0.113.41", "site-a", "browser-a"
	_, fields := capChallengePage(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	if decision, err := p.failureTracker.RecordFailure(p.failureKey(ip, site)); err != nil || decision.Level == 0 {
		t.Fatalf("failed to trigger behavior escalation: decision=%+v err=%v", decision, err)
	}

	result := postCapAnswer(p, "https://site-a/private", ip, site, ua, fields)
	if result.Code != http.StatusForbidden || !strings.Contains(result.Body.String(), `id="stage"`) || strings.Contains(result.Body.String(), "<cap-widget") {
		t.Fatalf("escalated challenge did not stay native: status=%d body=%q", result.Code, result.Body.String())
	}
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == p.cookieName {
			t.Fatalf("stale Cap answer issued WAF clearance: %+v", cookie)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("stale Cap answer reached siteverify %d times", calls.Load())
	}
}

func TestCapBotBehaviorChallengeRemainsNative(t *testing.T) {
	p, calls := newCapBotPolicy(t, nil, "shape_slider")
	req := httptest.NewRequest(http.MethodGet, "https://site-a/private", nil)
	req.Host = "site-a"
	req.Header.Set("User-Agent", "browser-a")
	rec := httptest.NewRecorder()
	p.ServeChallengeForSite(rec, req, "203.0.113.38", "site-a")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `id="stage"`) || strings.Contains(rec.Body.String(), "<cap-widget") {
		t.Fatalf("behavior challenge was unexpectedly replaced: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("behavior challenge called Cap siteverify %d times", calls.Load())
	}
}
