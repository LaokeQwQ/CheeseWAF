package bot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type behaviorPageTestState struct {
	Challenge  captcha.BehaviorChallenge `json:"challenge"`
	ReturnURL  string                    `json:"returnURL"`
	Idempotent bool                      `json:"idempotent"`
}

var behaviorStatePattern = regexp.MustCompile(`const S=(\{.*\});\s*\n`)

func newBehaviorPolicy(t *testing.T, mutate func(*config.BotProtectionConfig)) *Policy {
	t.Helper()
	cfg := config.Default().Protection.Bot
	cfg.Enabled = true
	cfg.CAPTCHA = true
	cfg.CAPTCHAType = "random"
	cfg.CAPTCHATypes = []string{"pow"}
	cfg.CAPTCHAEscalationTypes = []string{"pow", "shape_slider"}
	cfg.CAPTCHAMaxAttempts = 3
	cfg.Secret = strings.Repeat("s", 48)
	cfg.CookieName = "cw_clearance"
	cfg.ChallengeTTL = 10 * time.Minute
	cfg.CAPTCHAChallengeTTL = 2 * time.Minute
	cfg.CAPTCHAPolicyVersion = "test-v1"
	if mutate != nil {
		mutate(&cfg)
	}
	return NewPolicy(cfg)
}

func issueBehaviorPOW(t *testing.T, p *Policy, method, target, clientIP, site, ua string) (behaviorPageTestState, captcha.BehaviorResponse, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = site
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	p.ServeChallengeForSite(rec, req, clientIP, site)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("challenge status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("behavior challenge security headers missing: %v", rec.Header())
	}
	match := behaviorStatePattern.FindStringSubmatch(rec.Body.String())
	if len(match) != 2 {
		t.Fatalf("behavior state not found in page")
	}
	var state behaviorPageTestState
	if err := json.Unmarshal([]byte(match[1]), &state); err != nil {
		t.Fatal(err)
	}
	response := captcha.BehaviorResponse{Token: state.Challenge.Token}
	if state.Challenge.Type == captcha.BehaviorPOW {
		proof, ok := captcha.SolveBehaviorPOW(state.Challenge.Presentation.POWSalt, state.Challenge.Presentation.POWDifficulty, 1<<24)
		if !ok {
			t.Fatal("could not solve behavior pow")
		}
		response.Proof = proof
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("behavior owner cookie missing")
	}
	return state, response, cookies[0]
}

func verifyBehavior(t *testing.T, p *Policy, response captcha.BehaviorResponse, clientIP, site, ua string, ownerCookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, behaviorVerifyEndpoint, strings.NewReader(string(body)))
	req.Host = site
	req.Header.Set("User-Agent", ua)
	for _, cookie := range ownerCookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	p.VerifyBehaviorChallenge(rec, req, clientIP, site, true)
	return rec
}

func TestBehaviorChallengeSuccessReplayAndClearanceBinding(t *testing.T) {
	p := newBehaviorPolicy(t, nil)
	const ip, site, ua = "203.0.113.9", "site-a", "browser-a"
	state, response, ownerCookie := issueBehaviorPOW(t, p, http.MethodGet, "https://site-a/account?next=1", ip, site, ua)
	if state.ReturnURL != "/account?next=1" || !state.Idempotent {
		t.Fatalf("unexpected page semantics: %+v", state)
	}
	rec := verifyBehavior(t, p, response, ip, site, ua, ownerCookie)
	if rec.Code != http.StatusOK || rec.Header().Get("Set-Cookie") == "" || !strings.Contains(rec.Body.String(), `"clearance":true`) {
		t.Fatalf("verify status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
	}
	cookie := rec.Result().Cookies()[0]
	allowed := httptest.NewRequest(http.MethodGet, "https://site-a/account", nil)
	allowed.Host = site
	allowed.Header.Set("User-Agent", ua)
	allowed.AddCookie(cookie)
	if result := p.EvaluateForSite(allowed, ip, site); result != nil {
		t.Fatalf("valid clearance rejected: %+v", result)
	}
	for _, changed := range []struct{ ip, site, ua string }{{"198.51.100.10", site, ua}, {ip, "site-b", ua}, {ip, site, "browser-b"}} {
		req := httptest.NewRequest(http.MethodGet, "https://"+changed.site+"/account", nil)
		req.Host = changed.site
		req.Header.Set("User-Agent", changed.ua)
		req.AddCookie(cookie)
		if result := p.EvaluateForSite(req, changed.ip, changed.site); result == nil {
			t.Fatalf("clearance accepted across binding: %+v", changed)
		}
	}
	if replay := verifyBehavior(t, p, response, ip, site, ua, ownerCookie); replay.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d body=%q", replay.Code, replay.Body.String())
	}
}

func TestBehaviorChallengeWrongConsumesAndConcurrentOnlyOnce(t *testing.T) {
	p := newBehaviorPolicy(t, nil)
	const ip, site, ua = "203.0.113.20", "site-a", "browser-a"
	_, response, ownerCookie := issueBehaviorPOW(t, p, http.MethodPost, "https://site-a/checkout", ip, site, ua)
	wrong := response
	wrong.Proof = "wrong"
	if rec := verifyBehavior(t, p, wrong, ip, site, ua, ownerCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong answer status=%d", rec.Code)
	}
	if rec := verifyBehavior(t, p, response, ip, site, ua, ownerCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("correct answer after consumed wrong answer status=%d", rec.Code)
	}

	p = newBehaviorPolicy(t, nil)
	_, response, ownerCookie = issueBehaviorPOW(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes <- verifyBehavior(t, p, response, ip, site, ua, ownerCookie).Code
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes=%d, want 1", successes)
	}
}

func TestBehaviorFailureBudgetSurvivesRefreshAndBlocks(t *testing.T) {
	p := newBehaviorPolicy(t, nil)
	const ip, site, ua = "203.0.113.30", "site-a", "browser-a"
	for attempt := 1; attempt <= 3; attempt++ {
		_, response, ownerCookie := issueBehaviorPOW(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
		response.Proof = "wrong"
		rec := verifyBehavior(t, p, response, ip, site, ua, ownerCookie)
		want := http.StatusUnauthorized
		if attempt == 3 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt, rec.Code, want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "https://site-a/private", nil)
	req.Host = site
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	p.ServeChallengeForSite(rec, req, ip, site)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked refresh status=%d", rec.Code)
	}
}

func TestBehaviorClearancePolicyVersionAndPostSemantics(t *testing.T) {
	p := newBehaviorPolicy(t, nil)
	const ip, site, ua = "203.0.113.40", "site-a", "browser-a"
	state, response, ownerCookie := issueBehaviorPOW(t, p, http.MethodPost, "https://site-a/orders?answer=kept-out", ip, site, ua)
	if state.Idempotent || !strings.Contains(state.ReturnURL, "/orders") {
		t.Fatalf("unexpected POST state: %+v", state)
	}
	if strings.Contains(state.ReturnURL, "cw_") {
		t.Fatalf("answer field leaked into return URL: %q", state.ReturnURL)
	}
	rec := verifyBehavior(t, p, response, ip, site, ua, ownerCookie)
	cookie := rec.Result().Cookies()[0]
	p.policyVersion = "test-v2"
	req := httptest.NewRequest(http.MethodGet, "https://site-a/orders", nil)
	req.Host = site
	req.Header.Set("User-Agent", ua)
	req.AddCookie(cookie)
	if result := p.EvaluateForSite(req, ip, site); result == nil {
		t.Fatal("clearance survived policy version change")
	}
}

func TestBehaviorOwnerCookieMissingOrTamperedDoesNotConsumePending(t *testing.T) {
	p := newBehaviorPolicy(t, nil)
	const ip, site, ua = "203.0.113.77", "site-a", "browser-a"
	_, response, ownerCookie := issueBehaviorPOW(t, p, http.MethodGet, "https://site-a/private", ip, site, ua)
	if rec := verifyBehavior(t, p, response, ip, site, ua); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing owner status=%d", rec.Code)
	}
	tampered := *ownerCookie
	tampered.Value += "x"
	if rec := verifyBehavior(t, p, response, ip, site, ua, &tampered); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered owner status=%d", rec.Code)
	}
	if rec := verifyBehavior(t, p, response, ip, site, ua, ownerCookie); rec.Code != http.StatusOK {
		t.Fatalf("valid owner lost pending after invalid attempts: %d %s", rec.Code, rec.Body.String())
	}
}
