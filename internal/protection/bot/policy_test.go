package bot

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestPolicyChallengesSuspiciousUserAgent(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:      true,
		JSChallenge:  true,
		ChallengeTTL: time.Minute,
		CookieName:   "cw_clearance",
		Secret:       "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("User-Agent", "curl/8.0")

	result := policy.Evaluate(req, "203.0.113.10")
	if result == nil || result.Action != engine.ActionChallenge || result.Category != "bot" {
		t.Fatalf("expected bot challenge, got %#v", result)
	}
}

func TestPolicyAllowsValidClearance(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:      true,
		JSChallenge:  true,
		ChallengeTTL: time.Minute,
		CookieName:   "cw_clearance",
		Secret:       "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	value, _ := policy.clearance(req, "203.0.113.10")
	req.AddCookie(&http.Cookie{Name: "cw_clearance", Value: value})

	if result := policy.Evaluate(req, "203.0.113.10"); result != nil {
		t.Fatalf("expected clearance to bypass challenge, got %#v", result)
	}
}

func TestPolicyClearanceHeaderScopeAndRevocation(t *testing.T) {
	p := NewPolicy(config.BotProtectionConfig{Enabled: true, JSChallenge: true, ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "01234567890123456789012345678901", ClearanceHeaderEnabled: true, ClearanceHeaderName: "X-API-Clearance", ClearanceMethodScope: true})
	issued := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	issued.Header.Set("User-Agent", "curl/8.0")
	token, _ := p.clearance(issued, "203.0.113.10")
	req := httptest.NewRequest(http.MethodGet, "https://example.test/private/items", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("X-API-Clearance", token)
	if got := p.Evaluate(req, "203.0.113.10"); got != nil {
		t.Fatalf("header clearance rejected: %#v", got)
	}
	post := httptest.NewRequest(http.MethodPost, "https://example.test/private/items", nil)
	post.Header = req.Header.Clone()
	if got := p.Evaluate(post, "203.0.113.10"); got == nil {
		t.Fatal("method scope bypassed")
	}
	if !p.RevokeClearance(token) {
		t.Fatal("revoke failed")
	}
	if got := p.Evaluate(req, "203.0.113.10"); got == nil {
		t.Fatal("revoked clearance accepted")
	}
}

func TestPoWResponseUsesOpaqueV2AndLegacyMigrationToggle(t *testing.T) {
	p := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "pow", ChallengeTTL: time.Minute, ChallengeDifficulty: 1, PoWMaxDifficulty: 2, ClearanceStateCapacity: 100, Secret: "01234567890123456789012345678901", PoWAcceptLegacy: false})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/api", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()
	p.ServeChallengeForSite(rr, req, "203.0.113.10", "example.test")
	auth := rr.Header().Values("WWW-Authenticate")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "CheeseWAF-Compute ") {
		t.Fatalf("auth=%v", auth)
	}
	metadata := auth[0]
	if end := strings.LastIndex(metadata, `"`); end >= 0 {
		metadata = metadata[end+1:]
	}
	if strings.Contains(strings.ToLower(metadata), "sha") || strings.Contains(strings.ToLower(metadata), "difficulty") || strings.Contains(auth[0], "PoW") || strings.Contains(metadata, "work=") {
		t.Fatalf("algorithm details leaked: %s", auth[0])
	}
}

func TestPolicyExemptsConfiguredPath(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:            true,
		JSChallenge:        true,
		ExemptPathPrefixes: []string{"/api/"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("User-Agent", "sqlmap")

	if result := policy.Evaluate(req, "203.0.113.10"); result != nil {
		t.Fatalf("expected exempt path to bypass challenge, got %#v", result)
	}
}

func TestPolicyRejectsPathTraversalExemptionBypass(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:            true,
		JSChallenge:        true,
		PathPrefixes:       []string{"/"},
		ExemptPathPrefixes: []string{"/api/", "/health"},
		Secret:             "test-secret",
	})

	cases := []struct {
		name string
		path string
	}{
		{"dotdot under api exemption", "/api/../admin"},
		{"dotdot under health exemption", "/health/../x"},
		{"health prefix without segment boundary", "/healthxyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("User-Agent", "sqlmap")
			result := policy.Evaluate(req, "203.0.113.10")
			if result == nil || !result.Detected {
				t.Fatalf("path %q must not be exempt from bot policy", tc.path)
			}
		})
	}

	// Legitimate exempt paths still bypass.
	for _, path := range []string{"/api/status", "/api", "/health", "/health/live"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("User-Agent", "sqlmap")
		if result := policy.Evaluate(req, "203.0.113.10"); result != nil {
			t.Fatalf("path %q should remain exempt, got %#v", path, result)
		}
	}
}

func TestPolicyAppliesSegmentBoundaryPrefixes(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:            true,
		PathPrefixes:       []string{"/admin"},
		ExemptPathPrefixes: []string{"/health"},
	})
	if !policy.applies("/admin") || !policy.applies("/admin/users") {
		t.Fatal("expected /admin and children to apply")
	}
	if policy.applies("/administrator") {
		t.Fatal("/administrator must not match path prefix /admin")
	}
	if policy.applies("/healthxyz") {
		t.Fatal("/healthxyz must not match exempt prefix /health")
	}
	if policy.applies("/health") || policy.applies("/health/ready") {
		t.Fatal("/health and children should be exempt")
	}
}

func TestChallengeWritesClearanceScript(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:             true,
		JSChallenge:         true,
		ChallengeDifficulty: 2,
		ChallengeTTL:        time.Minute,
		CookieName:          "cw_clearance",
		Secret:              "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	if rr.Code != http.StatusForbidden || !strings.Contains(body, "cw_pow_token") || strings.Contains(body, "cw_nonce") || !strings.Contains(body, "crypto.subtle") {
		t.Fatalf("unexpected challenge response: status=%d body=%s", rr.Code, body)
	}
}

func TestChallengeFailsClosedWhenRuntimeSecretGenerationFails(t *testing.T) {
	original := generateBotPolicySecret
	generateBotPolicySecret = func() (string, error) {
		return "", errors.New("entropy unavailable")
	}
	t.Cleanup(func() { generateBotPolicySecret = original })

	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:      true,
		CAPTCHA:      true,
		CAPTCHAType:  "slider",
		ChallengeTTL: time.Minute,
		CookieName:   "cw_clearance",
		Secret:       config.BotSecretPlaceholder,
	})
	if policy.secretReady {
		t.Fatal("expected policy to mark the signing secret unavailable")
	}
	if string(policy.secret) == "cheesewaf-ephemeral-bot-secret" {
		t.Fatal("policy must not fall back to the historical fixed bot secret")
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "bot challenge unavailable") {
		t.Fatalf("expected fail-closed challenge response, got status=%d body=%s", rr.Code, rr.Body.String())
	}
	req.Header.Set("X-CheeseWAF-Altcha", "challenge=invalid")
	if policy.validAltchaHeaderAnswer(req, "203.0.113.10") {
		t.Fatal("Altcha header must not verify without a ready signing secret")
	}
}

func TestAltchaChallengeWritesHeadersAndWidgetScript(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:          true,
		CAPTCHA:          true,
		AltchaMaxNumber:  5000,
		AltchaHeaderName: "X-CW-Altcha",
		ChallengeTTL:     time.Minute,
		CookieName:       "cw_clearance",
		Secret:           "test-secret",
		PoWAcceptLegacy:  true,
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	if rr.Code != http.StatusForbidden || !strings.Contains(body, "cw_altcha") || !strings.Contains(body, "maxnumber") {
		t.Fatalf("unexpected altcha response: status=%d body=%s", rr.Code, body)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), "Altcha challenge=") {
		t.Fatalf("missing altcha authenticate header: %+v", rr.Header())
	}
	if rr.Header().Get("X-Altcha-Authorization-Header") != "X-CW-Altcha" {
		t.Fatalf("unexpected altcha header hint %q", rr.Header().Get("X-Altcha-Authorization-Header"))
	}
}

func TestPoWChallengeFailsClosedWithNilManager(t *testing.T) {
	p := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "pow", ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "01234567890123456789012345678901"})
	p.powManager = nil
	rr := httptest.NewRecorder()
	p.ServeChallengeForSite(rr, httptest.NewRequest(http.MethodGet, "https://example.test/login", nil), "203.0.113.10", "example.test")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestImageCAPTCHAChallengeWritesImageAndAudioURL(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:      true,
		CAPTCHA:      true,
		CAPTCHAType:  "image",
		ChallengeTTL: time.Minute,
		CookieName:   "cw_clearance",
		Secret:       "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	if rr.Code != http.StatusForbidden || !strings.Contains(body, "cw_image_answer") || !strings.Contains(body, "cw_audio=") || !strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("unexpected image captcha response: status=%d body=%s", rr.Code, body)
	}
}

func TestImageCAPTCHAAudioURLReturnsWAV(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:      true,
		CAPTCHA:      true,
		CAPTCHAType:  "image",
		ChallengeTTL: time.Minute,
		CookieName:   "cw_clearance",
		Secret:       "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	challenge, err := policy.newImageChallenge(req, "203.0.113.10")
	if err != nil {
		t.Fatalf("image challenge: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/login?cw_audio="+url.QueryEscape(challenge.Token), nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "audio/wav" || !strings.HasPrefix(rr.Body.String(), "RIFF") {
		t.Fatalf("unexpected audio response: status=%d content-type=%q len=%d", rr.Code, rr.Header().Get("Content-Type"), rr.Body.Len())
	}
}

func TestImageCAPTCHAAudioURLIsRateLimitedPerChallenge(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:                true,
		CAPTCHA:                true,
		CAPTCHAType:            "image",
		ImageCAPTCHAAudioLimit: 2,
		ChallengeTTL:           time.Minute,
		CookieName:             "cw_clearance",
		Secret:                 "test-secret",
	})
	base := httptest.NewRequest(http.MethodGet, "/login", nil)
	base.Header.Set("User-Agent", "curl/8.0")
	challenge, err := policy.newImageChallenge(base, "203.0.113.10")
	if err != nil {
		t.Fatalf("image challenge: %v", err)
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login?cw_audio="+url.QueryEscape(challenge.Token), nil)
		req.Header.Set("User-Agent", "curl/8.0")
		rr := httptest.NewRecorder()
		policy.ServeChallenge(rr, req, "203.0.113.10")
		if rr.Code != http.StatusOK {
			t.Fatalf("audio play %d should be allowed, got status=%d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/login?cw_audio="+url.QueryEscape(challenge.Token), nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected audio rate limit, got status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCAPTCHAAnswerFailuresLockChallengeToken(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:            true,
		CAPTCHA:            true,
		CAPTCHAType:        "image",
		CAPTCHAMaxAttempts: 2,
		ChallengeTTL:       time.Minute,
		CookieName:         "cw_clearance",
		Secret:             "test-secret",
	})
	token := "opaque-token"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("cw_image_token="+url.QueryEscape(token)+"&cw_image_answer=bad"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "curl/8.0")
		if policy.validImageQueryAnswer(req, "203.0.113.10") {
			t.Fatal("fake image answer should not verify")
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("cw_image_token="+url.QueryEscape(token)+"&cw_image_answer=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "curl/8.0")
	if !policy.captchaLocked(req, "203.0.113.10", "image", token) {
		t.Fatal("expected challenge token to be locked after max failures")
	}
}

func TestCAPTCHAAttemptCapacityFailsClosedAndRecordsNewFailure(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:            true,
		CAPTCHA:            true,
		CAPTCHAType:        "image",
		CAPTCHAMaxAttempts: 2,
		ChallengeTTL:       time.Minute,
		CookieName:         "cw_clearance",
		Secret:             "test-secret",
	})
	request := httptest.NewRequest(http.MethodGet, "https://example.test/protected", nil)
	request.Header.Set("User-Agent", "browser-a")
	now := policy.now().Unix()
	policy.mu.Lock()
	for i := 0; i < maxCAPTCHAAttemptEntries; i++ {
		policy.attempts[fmt.Sprintf("filled-%d", i)] = captchaAttempt{expires: now + int64(i+1)}
	}
	policy.mu.Unlock()

	const token = "new-token"
	if !policy.captchaLocked(request, "203.0.113.10", "image", token) {
		t.Fatal("capacity saturation must fail closed for an untracked token")
	}
	policy.recordCAPTCHAAnswer(request, "203.0.113.10", "image", token, false)
	key := policy.captchaAttemptKey(request, "203.0.113.10", "image", token)
	policy.mu.Lock()
	attempt, ok := policy.attempts[key]
	length := len(policy.attempts)
	policy.mu.Unlock()
	if !ok || attempt.failures != 1 {
		t.Fatalf("new failure was not recorded after bounded eviction: %+v, present=%v", attempt, ok)
	}
	if length != maxCAPTCHAAttemptEntries {
		t.Fatalf("attempt store escaped capacity: got %d want %d", length, maxCAPTCHAAttemptEntries)
	}
}

func TestSliderCAPTCHAChallengeWritesPuzzleForm(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:      true,
		CAPTCHA:      true,
		CAPTCHAType:  "slider",
		ChallengeTTL: time.Minute,
		CookieName:   "cw_clearance",
		Secret:       "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	if rr.Code != http.StatusForbidden || !strings.Contains(body, "cw_slider_token") || !strings.Contains(body, "cw_slider_x") || !strings.Contains(body, "slider-piece") {
		t.Fatalf("unexpected slider captcha response: status=%d body=%s", rr.Code, body)
	}
	if !strings.Contains(body, "slider-notice") || !strings.Contains(body, "slider-refresh") || !strings.Contains(body, "captcha-foot") {
		t.Fatalf("expected product slider card markup, body=%s", body)
	}
	if strings.Contains(body, "slider-submit") || strings.Contains(body, "鈫") {
		t.Fatalf("legacy slider markup leaked into response: %s", body)
	}
	for _, marker := range []string{`role="slider"`, `aria-valuemin="0"`, `thumb.addEventListener("keydown"`, `event.key === "ArrowLeft"`, `event.key === "Enter"`, `type:"down"`, `type:"move"`, `type:"up"`, `const minDragMS = `, `Math.max(minDragMS, 500)`, `prefers-reduced-motion:reduce`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected accessible slider marker %q, body=%s", marker, body)
		}
	}
}

func TestChallengeResponsesSetSecurityHeadersAndNonce(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "slider", ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret"})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/login", nil)
	rec := httptest.NewRecorder()
	policy.ServeChallenge(rec, req, "203.0.113.10")
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "style-src 'nonce-") {
		t.Fatalf("challenge CSP is incomplete: %q", csp)
	}
	for name, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if got := rec.Header().Get(name); got != want {
			t.Fatalf("%s=%q want %q", name, got, want)
		}
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<style nonce="`) || !strings.Contains(body, `<script nonce="`) {
		t.Fatal("challenge document did not bind inline resources to the CSP nonce")
	}
}

func TestWaitingRoomSetsSecurityHeadersAndNonce(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, WaitingRoom: true, WaitingRoomMaxActive: 1, WaitingRoomTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret"})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/shop", nil)
	rec := httptest.NewRecorder()
	policy.ServeChallenge(rec, req, "203.0.113.10")
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("waiting room security headers missing: %v", rec.Header())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<style nonce="`) || !strings.Contains(body, `<script nonce="`) {
		t.Fatal("waiting room did not bind inline resources to the CSP nonce")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "cw_clearance_queue" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("expected Secure HttpOnly waiting-room cookie, got %+v", cookies)
	}
	if strings.Contains(body, "document.cookie") {
		t.Fatal("waiting room must not set ticket via document.cookie")
	}
}

func TestChallengeLocalizesFromAcceptLanguage(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "slider", ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret"})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.7")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	for _, marker := range []string{`<html lang="zh-CN">`, `<title>浏览器验证</title>`, `滑块拼图验证码图片`, `aria-label="刷新验证"`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected localized challenge marker %q, body=%s", marker, body)
		}
	}
}

func TestChallengeDefaultsToEnglish(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, JSChallenge: true, ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret"})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, req, "203.0.113.10")
	if body := rr.Body.String(); !strings.Contains(body, `<html lang="en">`) || !strings.Contains(body, `<title>Browser verification</title>`) {
		t.Fatalf("expected English fallback challenge, body=%s", body)
	}
}

func TestSliderCAPTCHAUsesMobileFallback(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:           true,
		CAPTCHA:           true,
		CAPTCHAType:       "slider",
		CAPTCHAMobileType: "pow",
		ChallengeTTL:      time.Minute,
		CookieName:        "cw_clearance",
		Secret:            "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	if rr.Code != http.StatusForbidden || !strings.Contains(body, "cw_pow_token") || strings.Contains(body, "cw_altcha") || strings.Contains(body, "cw_slider_token") {
		t.Fatalf("expected mobile fallback PoW challenge, status=%d body=%s", rr.Code, body)
	}
}

func TestCleanChallengeURLDropsCAPTCHAPayloadFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login?keep=1&cw_slider_token=t&cw_slider_x=10&cw_slider_drag_ms=500&cw_slider_track=%5B%5D&cw_audio=a&cw_pow=1", nil)
	cleaned := cleanChallengeURL(req)
	for _, leaked := range []string{"cw_slider_token", "cw_slider_x", "cw_slider_drag_ms", "cw_slider_track", "cw_audio", "cw_pow"} {
		if strings.Contains(cleaned, leaked) {
			t.Fatalf("challenge payload field %q leaked into cleaned URL %q", leaked, cleaned)
		}
	}
	if !strings.Contains(cleaned, "keep=1") {
		t.Fatalf("unrelated query parameter was lost: %q", cleaned)
	}
}

func TestSafeChallengeReturnURLRejectsAbsoluteRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "//evil.example/path?cw_pow=1", nil)
	if got := safeChallengeReturnURL(req); got != "/" {
		t.Fatalf("expected absolute redirect target to be rejected, got %q", got)
	}
}

func TestChallengeValidatesProofAndSetsClearance(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:             true,
		JSChallenge:         true,
		ChallengeDifficulty: 2,
		ChallengeTTL:        time.Minute,
		CookieName:          "cw_clearance",
		Secret:              "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	ctx := PoWContext{Site: canonicalSite(req.Host), Policy: "bot", PolicyVersion: policy.policyVersion, Path: req.URL.Path, ClientKey: "203.0.113.10\n" + req.UserAgent()}
	challenge, err := policy.powManager.Issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer := ""
	for i := 0; ; i++ {
		candidate := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge.Token + "\x00" + candidate))
		if hasLeadingZeroNibbles(sum[:], challenge.Work) {
			answer = candidate
			break
		}
	}
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"cw_pow_token": {challenge.Token}, "cw_pow_answer": {answer}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after valid proof, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Result().Cookies(); len(got) != 1 || got[0].Name != "cw_clearance" {
		t.Fatalf("expected clearance cookie, got %+v", got)
	}
}

func TestChallengeRejectsNewPoWTokenInQuery(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, JSChallenge: true, ChallengeDifficulty: 1, ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret"})
	base := httptest.NewRequest(http.MethodGet, "/login", nil)
	base.Header.Set("User-Agent", "curl/8.0")
	ctx := PoWContext{Site: canonicalSite(base.Host), Policy: "bot", PolicyVersion: policy.policyVersion, Path: base.URL.Path, ClientKey: "203.0.113.10\n" + base.UserAgent()}
	challenge, err := policy.powManager.Issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer := ""
	for i := 0; ; i++ {
		candidate := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge.Token + "\x00" + candidate))
		if hasLeadingZeroNibbles(sum[:], challenge.Work) {
			answer = candidate
			break
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/login?cw_pow_token="+url.QueryEscape(challenge.Token)+"&cw_pow_answer="+url.QueryEscape(answer), nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusForbidden || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("new PoW query payload was accepted: status=%d cookies=%v", rr.Code, rr.Result().Cookies())
	}
}
func TestChallengePageFloodDoesNotConsumeClearanceCapacity(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, JSChallenge: true, ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret", ClearanceStateCapacity: 1})
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		rr := httptest.NewRecorder()
		policy.ServeChallenge(rr, req, "203.0.113.10")
		want := http.StatusServiceUnavailable
		if i == 0 {
			want = http.StatusForbidden
		}
		if rr.Code != want {
			t.Fatalf("challenge page %d returned %d, want %d", i, rr.Code, want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	if token, _ := policy.clearance(req, "203.0.113.10"); token == "" {
		t.Fatal("challenge page display exhausted clearance capacity")
	}
}

func TestValidChallengeFailsClosedWhenClearanceCapacityExhausted(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, JSChallenge: true, ChallengeDifficulty: 1, ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret", ClearanceStateCapacity: 1})
	occupied := httptest.NewRequest(http.MethodGet, "/occupied", nil)
	occupied.Header.Set("User-Agent", "curl/8.0")
	if token, _ := policy.clearance(occupied, "203.0.113.20"); token == "" {
		t.Fatal("failed to occupy clearance capacity")
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	ctx := PoWContext{Site: canonicalSite(req.Host), Policy: "bot", PolicyVersion: policy.policyVersion, Path: req.URL.Path, ClientKey: "203.0.113.10\n" + req.UserAgent()}
	challenge, err := policy.powManager.Issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer := ""
	for i := 0; ; i++ {
		candidate := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge.Token + "\x00" + candidate))
		if hasLeadingZeroNibbles(sum[:], challenge.Work) {
			answer = candidate
			break
		}
	}
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"cw_pow_token": {challenge.Token}, "cw_pow_answer": {answer}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when clearance issuance fails, got %d body=%s", rr.Code, rr.Body.String())
	}
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("clearance failure must not set a cookie: %+v", cookies)
	}
	if location := rr.Header().Get("Location"); location != "" {
		t.Fatalf("clearance failure must not redirect, got %q", location)
	}
}

func TestChallengeClearanceCookieSecureBehindHTTPSProxy(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:             true,
		JSChallenge:         true,
		ChallengeDifficulty: 2,
		ChallengeTTL:        time.Minute,
		CookieName:          "cw_clearance",
		Secret:              "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	ctx := PoWContext{Site: canonicalSite(req.Host), Policy: "bot", PolicyVersion: policy.policyVersion, Path: req.URL.Path, ClientKey: "203.0.113.10\n" + req.UserAgent()}
	challenge, err := policy.powManager.Issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer := ""
	for i := 0; ; i++ {
		candidate := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge.Token + "\x00" + candidate))
		if hasLeadingZeroNibbles(sum[:], challenge.Work) {
			answer = candidate
			break
		}
	}
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"cw_pow_token": {challenge.Token}, "cw_pow_answer": {answer}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("expected secure httponly clearance cookie behind https proxy, got %+v", cookies)
	}
}

func TestAltchaQueryPayloadSetsClearance(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:         true,
		CAPTCHA:         true,
		AltchaMaxNumber: 5000,
		ChallengeTTL:    time.Minute,
		CookieName:      "cw_clearance",
		Secret:          "test-secret",
		PoWAcceptLegacy: true,
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	challenge, err := policy.newAltchaChallenge(req, "203.0.113.10")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	payload := solveAltchaPayload(t, challenge)
	req = httptest.NewRequest(http.MethodGet, "/login?cw_altcha="+url.QueryEscape(payload), nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect after valid altcha, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Result().Cookies(); len(got) != 1 || got[0].Name != "cw_clearance" {
		t.Fatalf("expected clearance cookie, got %+v", got)
	}
}

func TestAltchaHeaderPayloadBypassesChallenge(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:              true,
		CAPTCHA:              true,
		AltchaMaxNumber:      5000,
		AltchaHeaderName:     "X-CW-Altcha",
		SuspiciousUserAgents: []string{"curl"},
		ChallengeTTL:         time.Minute,
		CookieName:           "cw_clearance",
		Secret:               "test-secret",
		ExemptPathPrefixes:   []string{"/health"},
		PathPrefixes:         []string{"/"},
		WaitingRoomMaxActive: 1000,
		WaitingRoomTTL:       time.Minute,
		ChallengeDifficulty:  2,
		PoWAcceptLegacy:      true,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/private", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	challenge, err := policy.newAltchaChallenge(req, "203.0.113.10")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	req.Header.Set("X-CW-Altcha", solveAltchaPayload(t, challenge))

	if result := policy.Evaluate(req, "203.0.113.10"); result != nil {
		t.Fatalf("expected valid altcha header to bypass challenge, got %#v", result)
	}
}

func TestAltchaLegacyDisabledByDefaultAndReplaySharedAcrossInputs(t *testing.T) {
	base := config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "pow", AltchaMaxNumber: 1000, AltchaHeaderName: "X-CW-Altcha", ChallengeTTL: time.Minute, ChallengeDifficulty: 1, PoWMaxDifficulty: 2, ClearanceStateCapacity: 100, Secret: "01234567890123456789012345678901"}
	disabled := NewPolicy(base)
	req := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	challenge, err := disabled.newAltchaChallenge(req, "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	payload := solveAltchaPayload(t, challenge)
	req.Header.Set("X-CW-Altcha", payload)
	if disabled.validAltchaHeaderAnswer(req, "203.0.113.10") {
		t.Fatal("legacy Altcha accepted while disabled")
	}

	base.PoWAcceptLegacy = true
	enabled := NewPolicy(base)
	req = httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	challenge, err = enabled.newAltchaChallenge(req, "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	payload = solveAltchaPayload(t, challenge)
	req.Header.Set("X-CW-Altcha", payload)
	if !enabled.validAltchaHeaderAnswer(req, "203.0.113.10") {
		t.Fatal("issued legacy Altcha rejected")
	}
	replay := httptest.NewRequest(http.MethodGet, "https://example.test/private?cw_altcha="+url.QueryEscape(payload), nil)
	replay.Header.Set("User-Agent", "curl/8.0")
	if enabled.validAltchaQueryAnswer(replay, "203.0.113.10") {
		t.Fatal("header proof replayed through query input")
	}
}

func TestClearanceStrictVersionDispatchAndAuthenticatedRevocation(t *testing.T) {
	p := NewPolicy(config.BotProtectionConfig{Enabled: true, ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: "01234567890123456789012345678901", ClearanceStateCapacity: 100})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	req.Header.Set("User-Agent", "UA")
	token, _ := p.clearance(req, "203.0.113.10")
	if token == "" {
		t.Fatal("clearance not issued")
	}
	parts := strings.Split(token, ".")
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("invalid-signature"))
	if p.RevokeClearance(forged) {
		t.Fatal("forged token revoked clearance")
	}
	req.AddCookie(&http.Cookie{Name: "cw_clearance", Value: token})
	if !p.hasClearance(req, "203.0.113.10") {
		t.Fatal("forged revocation invalidated legitimate clearance")
	}
	if !p.RevokeClearance(token) || p.hasClearance(req, "203.0.113.10") {
		t.Fatal("authenticated revocation failed")
	}

	expires := p.now().Add(time.Minute).Unix()
	legacy := strconv.FormatInt(expires, 10) + ":" + p.sign(req, "203.0.113.10", expires)
	req2 := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	req2.Header.Set("User-Agent", "UA")
	req2.AddCookie(&http.Cookie{Name: "cw_clearance", Value: legacy})
	if p.hasClearance(req2, "203.0.113.10") {
		t.Fatal("legacy clearance accepted by default")
	}
	p.clearanceAcceptLegacy = true
	if !p.hasClearance(req2, "203.0.113.10") {
		t.Fatal("explicit legacy clearance migration rejected")
	}
	badNew := token[:len(token)-1] + "A"
	req3 := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	req3.Header.Set("User-Agent", "UA")
	req3.AddCookie(&http.Cookie{Name: "cw_clearance", Value: badNew})
	if p.hasClearance(req3, "203.0.113.10") {
		t.Fatal("invalid versioned token downgraded to legacy parser")
	}
}

func TestAltchaParserRejectsOversizedPayload(t *testing.T) {
	if _, ok := parseAltchaPayload(strings.Repeat("A", 4097)); ok {
		t.Fatal("oversized Altcha payload accepted")
	}
}

func TestCAPTCHAQueryInputsRejectOversizedValues(t *testing.T) {
	p := NewPolicy(config.BotProtectionConfig{Enabled: true, CAPTCHA: true, CAPTCHAType: "slider", ChallengeTTL: time.Minute, Secret: "01234567890123456789012345678901"})
	imageBody := "cw_image_token=" + url.QueryEscape(strings.Repeat("A", maxCAPTCHATokenBytes+1)) + "&cw_image_answer=1"
	imageReq := httptest.NewRequest(http.MethodPost, "https://example.test/", strings.NewReader(imageBody))
	imageReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.validImageQueryAnswer(imageReq, "203.0.113.10") {
		t.Fatal("oversized image token accepted")
	}
	sliderBody := "cw_slider_token=token&cw_slider_x=1&cw_slider_drag_ms=500&cw_slider_track=" + url.QueryEscape(strings.Repeat("x", maxSliderTrackBytes+1))
	sliderReq := httptest.NewRequest(http.MethodPost, "https://example.test/", strings.NewReader(sliderBody))
	sliderReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.validSliderQueryAnswer(sliderReq, "203.0.113.10") {
		t.Fatal("oversized slider track accepted")
	}
}

func TestWaitingRoomIssuesTicketBeforeBotChallenge(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:              true,
		WaitingRoom:          true,
		WaitingRoomMaxActive: 1,
		WaitingRoomTTL:       time.Minute,
		JSChallenge:          false,
		CookieName:           "cw_clearance",
		Secret:               "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/shop", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	result := policy.Evaluate(req, "203.0.113.10")
	if result == nil || result.Category != "waiting_room" || result.Action != engine.ActionChallenge {
		t.Fatalf("expected waiting room challenge, got %#v", result)
	}
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected waiting room page, status=%d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "cw_clearance_queue" || !cookies[0].HttpOnly {
		t.Fatalf("expected server-side HttpOnly waiting-room cookie, got %+v", cookies)
	}
	if strings.Contains(rr.Body.String(), "document.cookie") {
		t.Fatal("waiting room must not set ticket via document.cookie")
	}
}

func TestWaitingRoomRespectsCapacity(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled:              true,
		WaitingRoom:          true,
		WaitingRoomMaxActive: 1,
		WaitingRoomTTL:       time.Minute,
		CookieName:           "cw_clearance",
		Secret:               "test-secret",
	})
	req := httptest.NewRequest(http.MethodGet, "/shop", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	policy.waitingTicket(req, "203.0.113.10")

	next := httptest.NewRequest(http.MethodGet, "/shop", nil)
	next.Header.Set("User-Agent", "Mozilla/5.0 other")
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, next, "203.0.113.11")
	if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), "protected service is busy") {
		t.Fatalf("expected full waiting room, status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWaitingRoomLocalizesFromAcceptLanguage(t *testing.T) {
	policy := NewPolicy(config.BotProtectionConfig{Enabled: true, WaitingRoom: true, WaitingRoomMaxActive: 1, WaitingRoomTTL: time.Minute, CookieName: "cw_clearance", Secret: "test-secret"})
	req := httptest.NewRequest(http.MethodGet, "/shop", nil)
	req.Header.Set("Accept-Language", "zh-TW,zh;q=0.8")
	rr := httptest.NewRecorder()
	policy.ServeChallenge(rr, req, "203.0.113.10")
	body := rr.Body.String()
	if !strings.Contains(body, `<html lang="zh-CN">`) || !strings.Contains(body, `<title>排队等待</title>`) {
		t.Fatalf("expected localized waiting room, body=%s", body)
	}
}

func solveTestProof(nonce string, difficulty int) string {
	for i := 0; i < 1_000_000; i++ {
		answer := strconv.Itoa(i)
		if validProof(nonce, answer, difficulty) {
			return answer
		}
	}
	return ""
}

func solveAltchaPayload(t *testing.T, challenge altchaChallenge) string {
	t.Helper()
	for i := 0; i <= challenge.MaxNumber; i++ {
		if altchaHash(challenge.Salt, i) == challenge.Challenge {
			payload, err := json.Marshal(altchaPayload{
				Algorithm: challenge.Algorithm,
				Challenge: challenge.Challenge,
				Number:    i,
				Salt:      challenge.Salt,
				Signature: challenge.Signature,
			})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			return base64.StdEncoding.EncodeToString(payload)
		}
	}
	t.Fatalf("failed to solve altcha challenge %+v", challenge)
	return ""
}

func TestImageCAPTCHAFullCycleIssueAnswerConsume(t *testing.T) {
	secret := "01234567890123456789012345678901"
	policy := NewPolicy(config.BotProtectionConfig{
		Enabled: true, CAPTCHA: true, CAPTCHAType: "image",
		ChallengeTTL: time.Minute, CookieName: "cw_clearance", Secret: secret,
		PathPrefixes: []string{"/"},
	})
	const clientIP = "203.0.113.40"
	const site = "app.example"
	issueReq := httptest.NewRequest(http.MethodGet, "https://app.example/login", nil)
	issueReq.Header.Set("User-Agent", "browser/1.0")
	issueReq.Host = site
	challenge, err := policy.newImageChallengeForSite(issueReq, clientIP, site)
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	opts := policy.imageOptionsForSite(issueReq, clientIP, site)
	answer, ok := captcha.ImageTokenAnswer(opts, challenge.Token)
	if !ok || answer == "" {
		t.Fatalf("decode answer ok=%v answer=%q", ok, answer)
	}
	form := url.Values{}
	form.Set("cw_image_token", challenge.Token)
	form.Set("cw_image_answer", answer)
	post := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://app.example/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "browser/1.0")
		req.Host = site
		return req
	}
	if !policy.validImageQueryAnswerForSite(post(), clientIP, site) {
		t.Fatal("expected correct image answer to verify once")
	}
	if policy.validImageQueryAnswerForSite(post(), clientIP, site) {
		t.Fatal("replay of consumed image answer should fail")
	}
	// Full ServeChallenge path should set clearance on first correct POST.
	challenge2, err := policy.newImageChallengeForSite(issueReq, clientIP, site)
	if err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	answer2, ok := captcha.ImageTokenAnswer(opts, challenge2.Token)
	if !ok {
		t.Fatal("decode second answer")
	}
	form.Set("cw_image_token", challenge2.Token)
	form.Set("cw_image_answer", answer2)
	rr := httptest.NewRecorder()
	policy.ServeChallengeForSite(rr, post(), clientIP, site)
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Fatalf("expected redirect after success, status=%d", rr.Code)
	}
	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "cw_clearance=") {
		t.Fatalf("missing clearance cookie: %q", cookie)
	}
	if !strings.Contains(strings.ToLower(cookie), "secure") {
		t.Fatalf("https issue should set Secure clearance cookie: %q", cookie)
	}
}
