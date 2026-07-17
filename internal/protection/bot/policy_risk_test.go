package bot

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type botPolicyTestClock struct{ now time.Time }

func (c botPolicyTestClock) Now() time.Time { return c.now }

func TestPoWChallengeWorkTracksRiskBandAndRespectsMaximum(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "pow", ChallengeDifficulty: 1,
		PoWMaxDifficulty: 2, Secret: "test-secret", ClearanceStateCapacity: 100,
	})
	issueWork := func(t *testing.T, ua string, headers map[string]string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "https://example.test/login", nil)
		req.Header.Set("User-Agent", ua)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		rr := httptest.NewRecorder()
		policy.ServeChallengeForSite(rr, req, "203.0.113.10", "example.test")
		match := regexp.MustCompile(`target=([0-9]+)`).FindStringSubmatch(rr.Header().Get("WWW-Authenticate"))
		if len(match) != 2 {
			t.Fatalf("missing PoW work: %q", rr.Header().Get("WWW-Authenticate"))
		}
		work, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		return work
	}
	trusted := issueWork(t, "Mozilla/5.0", map[string]string{"Accept": "text/html", "Accept-Language": "en"})
	highRisk := issueWork(t, "sqlmap nuclei", nil)
	if highRisk <= trusted {
		t.Fatalf("risk band did not increase work: trusted=%d high=%d", trusted, highRisk)
	}
	if highRisk != 2 {
		t.Fatalf("PoW work exceeded or missed configured maximum: got=%d max=2", highRisk)
	}
}

func TestPolicyUsesInjectedClockForBehaviorTTL(t *testing.T) {
	now := time.Date(2026, time.July, 15, 11, 0, 0, 0, time.UTC)
	policy := NewPolicyWithClock(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "shape_slider", CAPTCHAChallengeTTL: 90 * time.Second,
		Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
	}, botPolicyTestClock{now: now})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/protected", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	challenge, err := policy.issueBehaviorChallenge(policy.behaviorOptions(req, "203.0.113.10", "example.test", captcha.BehaviorShapeSlider, "/protected"))
	if err != nil {
		t.Fatalf("issue behavior challenge: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, challenge.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiry: %v", err)
	}
	if want := now.Add(90 * time.Second); !expires.Equal(want) {
		t.Fatalf("challenge expiry = %v, want %v", expires, want)
	}
}

func TestAdaptiveRiskDecisionMatrix(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, JSChallenge: true, CAPTCHA: true, CAPTCHAType: "shape_slider",
		CAPTCHATypes: []string{"pow", "shape_slider"}, CAPTCHAEscalationTypes: []string{"shape_slider", "text_click"},
		Secret: "test-secret", RiskLevel: 2, RiskLowThreshold: 35, RiskMediumThreshold: 55,
		RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
	})
	tests := []struct {
		name, method, path, ua string
		headers                map[string]string
		wantAction             engine.Action
		wantNil                bool
	}{
		{name: "trusted browser", method: http.MethodGet, path: "/", ua: "Mozilla/5.0", headers: map[string]string{"Accept": "text/html", "Accept-Language": "en"}, wantNil: true},
		{name: "low suspicious", method: http.MethodGet, path: "/", ua: "curl/8.0", headers: map[string]string{"Accept": "*/*"}, wantAction: engine.ActionChallenge},
		{name: "medium automation", method: http.MethodPost, path: "/login", ua: "python-requests/2", wantAction: engine.ActionChallenge},
		{name: "extreme scanner", method: http.MethodPost, path: "/.env", ua: "sqlmap nuclei", wantAction: engine.ActionBlock},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("User-Agent", tc.ua)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			got := policy.EvaluateForSite(req, "203.0.113.10", "example.test")
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected allow, got %+v", got)
				}
				return
			}
			if got == nil || got.Action != tc.wantAction {
				t.Fatalf("expected %v, got %+v", tc.wantAction, got)
			}
		})
	}
}

func TestRiskLevelChangesThresholdWithoutChangingScore(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Header.Set("User-Agent", "python-requests/2")
	base := config.BotProtectionConfig{Enabled: true, JSChallenge: true, Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6}
	base.RiskLevel = 1
	low := NewPolicy(base).assessRisk(req, "203.0.113.10", "example.test")
	base.RiskLevel = 5
	high := NewPolicy(base).assessRisk(req, "203.0.113.10", "example.test")
	if low.score != high.score || low.band >= high.band {
		t.Fatalf("level must only shift thresholds: low=%+v high=%+v", low, high)
	}
}

func TestAdaptiveCAPTCHATypeDoesNotDowngradeOnMobileOrWeakNetwork(t *testing.T) {
	// Spoofable client signals (Mobile UA, Save-Data/ECT) must not force PoW when a
	// stronger captcha type is configured.
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "shape_slider", Secret: "test-secret"})
	for _, setup := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("User-Agent", "Mozilla/5.0 Mobile") },
		func(r *http.Request) { r.Header.Set("User-Agent", "Mozilla/5.0"); r.Header.Set("Save-Data", "on") },
		func(r *http.Request) { r.Header.Set("User-Agent", "Mozilla/5.0"); r.Header.Set("ECT", "2g") },
	} {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		setup(req)
		if got := policy.adaptiveCAPTCHAType(req, "203.0.113.10", "example.test"); got != "shape_slider" {
			t.Fatalf("expected configured shape_slider (no spoofable downgrade), got %q", got)
		}
	}
}

func TestFailuresEscalateAndEventuallyBlock(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "pow", CAPTCHAMaxAttempts: 3, CAPTCHAEscalationTypes: []string{"shape_slider", "text_click"}, Secret: "test-secret"})
	key := policy.failureKey("203.0.113.10", "example.test")
	first, _ := policy.failureTracker.RecordFailure(key)
	second, _ := policy.failureTracker.RecordFailure(key)
	third, _ := policy.failureTracker.RecordFailure(key)
	if first.Level != 1 || second.Level != 2 || !third.Blocked {
		t.Fatalf("unexpected escalation: first=%+v second=%+v third=%+v", first, second, third)
	}
}

func TestAdaptiveCAPTCHATypeHonorsConfigAndEscalatesOnlyOnHighRisk(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "shape_slider", CAPTCHATypes: []string{"shape_slider"}, CAPTCHAEscalationTypes: []string{"text_click"}, Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6})
	// Low/medium risk must keep the configured type (no automatic PoW downgrade).
	// High risk may escalate to the strongest escalation type.
	tests := []struct{ name, method, path, ua, want string }{{"low", http.MethodGet, "/", "curl/8.0", "shape_slider"}, {"medium", http.MethodPost, "/login", "python-requests/2", "shape_slider"}, {"high", http.MethodGet, "/", "sqlmap", "text_click"}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("User-Agent", tc.ua)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")
			if got := policy.adaptiveCAPTCHAType(req, "203.0.113.10", "example.test"); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestRandomBehaviorTypeStaysWithinConfiguredWhitelistAndDefersToEscalation(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "random",
		CAPTCHATypes: []string{"curve_slider", "shape_slider"}, CAPTCHAEscalationTypes: []string{"text_click"},
		Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
	})
	allowed := map[captcha.BehaviorType]bool{captcha.BehaviorCurveSlider: true, captcha.BehaviorShapeSlider: true}
	for range 64 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en")
		if got := policy.behaviorTypeFor(req, "203.0.113.10", "example.test", 0); !allowed[got] {
			t.Fatalf("random type escaped configured whitelist: %q", got)
		}
	}
	highRisk := httptest.NewRequest(http.MethodGet, "/", nil)
	highRisk.Header.Set("User-Agent", "sqlmap")
	if got := policy.behaviorTypeFor(highRisk, "203.0.113.10", "example.test", 0); got != captcha.BehaviorTextClick {
		t.Fatalf("high risk must keep escalation priority, got %q", got)
	}
}

func TestRandomCAPTCHATypeHonorsClassicOnlyPools(t *testing.T) {
	for _, kind := range []string{"image", "slider"} {
		t.Run(kind, func(t *testing.T) {
			policy := NewPolicy(config.BotProtectionConfig{
				Enabled: true, CAPTCHA: true, CAPTCHAType: "random", CAPTCHATypes: []string{kind},
				Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en")
			selection := policy.adaptiveCAPTCHASelection(req, "203.0.113.10", "example.test")
			if selection.kind != kind {
				t.Fatalf("selection kind = %q, want %q", selection.kind, kind)
			}
			if selection.behavior {
				t.Fatalf("classic CAPTCHA %q must not enter the Behavior challenge path", kind)
			}
		})
	}
}

func TestRandomCAPTCHATypeUsesBehaviorShellForConfiguredPOW(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "random", CAPTCHATypes: []string{"pow"},
		Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")
	selection := policy.adaptiveCAPTCHASelection(req, "203.0.113.10", "example.test")
	if selection.kind != "pow" || !selection.behavior {
		t.Fatalf("random PoW selection must use shared Behavior shell, got %+v", selection)
	}
}

func TestRandomCAPTCHAAnswerTypeUsesSubmittedClassicToken(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "random", CAPTCHATypes: []string{"shape_slider"},
		Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
	})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("cw_image_token=opaque&cw_image_answer=ABC123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := policy.challengeAnswerType(req); got != "image" {
		t.Fatalf("answer type = %q, want image", got)
	}
}

func TestRandomClassicFailureCanRotateIntoBehaviorChallenge(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "random", CAPTCHATypes: []string{"shape_slider"},
		Secret: "test-secret", RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6,
	})
	req := httptest.NewRequest(http.MethodPost, "https://example.test/protected", strings.NewReader("cw_image_token=invalid&cw_image_answer=ABC123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")
	recorder := httptest.NewRecorder()
	policy.ServeChallengeForSite(recorder, req, "203.0.113.10", "example.test")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"type":"shape_slider"`) {
		t.Fatalf("expected replacement Behavior challenge, body=%s", recorder.Body.String())
	}
}

func TestAllowedUserAgentUsesTokenMatchNotSubstring(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, JSChallenge: true, Secret: "test-secret",
		AllowedUserAgents: []string{"Googlebot", "bingbot"},
	})
	// Exact / whole-token matches should be allowed.
	for _, ua := range []string{
		"Googlebot",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	} {
		if !policy.allowed(ua) {
			t.Fatalf("expected allowlisted UA %q to match", ua)
		}
	}
	// Substring embedding must not bypass challenges.
	for _, ua := range []string{
		"evilgooglebot",
		"notgooglebotx",
		"mybingbotclient",
		"curl/8.0",
	} {
		if policy.allowed(ua) {
			t.Fatalf("substring UA %q must not match allowlist", ua)
		}
	}
}

func TestBehaviorOwnerCookieAlwaysSecureHttpOnly(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "shape_slider", Secret: "test-secret", CookieName: "cw_clearance",
	})
	// Clearance cookies are always Secure+HttpOnly (TLS is required for browser storage).
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "http://example.test/", nil),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			return r
		}(),
	} {
		_, cookie, err := policy.behaviorOwner(req, "example.test", true, cookieSecure(req))
		if err != nil {
			t.Fatal(err)
		}
		if !cookie.Secure || !cookie.HttpOnly {
			t.Fatalf("expected Secure HttpOnly owner cookie, got %#v", cookie)
		}
	}
}

func TestLowRiskClearanceIsShortLivedAndDoesNotMaskRiskIncrease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, JSChallenge: true, CAPTCHA: true, CAPTCHAType: "shape_slider", Secret: "test-secret", ChallengeTTL: 30 * time.Minute, ClearanceStateCapacity: 100, RiskLowThreshold: 35, RiskMediumThreshold: 55, RiskHighThreshold: 75, RiskBlockThreshold: 95, RiskConfidenceMin: 0.6})
	policy.now = func() time.Time { return now }
	policy.clearanceSigner.now = policy.now
	policy.clearanceState.now = policy.now
	low := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	low.Header.Set("User-Agent", "curl/8.0")
	low.Header.Set("Accept", "text/html")
	low.Header.Set("Accept-Language", "en")
	token, maxAge, err := policy.issueClearanceForRisk(low, "203.0.113.10", riskLow, "pow")
	if err != nil {
		t.Fatal(err)
	}
	if maxAge != int(lowRiskClearanceTTL.Seconds()) {
		t.Fatalf("expected low-risk max age %v, got %v", lowRiskClearanceTTL, time.Duration(maxAge)*time.Second)
	}
	low.AddCookie(&http.Cookie{Name: policy.cookieName, Value: token})
	if got := policy.EvaluateForSite(low, "203.0.113.10", "example.test"); got != nil {
		t.Fatalf("verified low-risk request should pass, got %+v", got)
	}
	higher := httptest.NewRequest(http.MethodPost, "https://example.test/login", nil)
	higher.Header.Set("User-Agent", "python-requests/2")
	higher.Header.Set("Accept", "text/html")
	higher.Header.Set("Accept-Language", "en")
	higher.AddCookie(&http.Cookie{Name: policy.cookieName, Value: token})
	if got := policy.EvaluateForSite(higher, "203.0.113.10", "example.test"); got == nil || got.Action != engine.ActionChallenge {
		t.Fatalf("risk increase must re-enter verification, got %+v", got)
	}
}
