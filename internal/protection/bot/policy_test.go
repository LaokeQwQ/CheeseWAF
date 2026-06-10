package bot

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

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
	if rr.Code != http.StatusForbidden || !strings.Contains(body, "cw_nonce") || !strings.Contains(body, "crypto.subtle") {
		t.Fatalf("unexpected challenge response: status=%d body=%s", rr.Code, body)
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
		req := httptest.NewRequest(http.MethodGet, "/login?cw_image_token="+url.QueryEscape(token)+"&cw_image_answer=bad", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		if policy.validImageQueryAnswer(req, "203.0.113.10") {
			t.Fatal("fake image answer should not verify")
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/login?cw_image_token="+url.QueryEscape(token)+"&cw_image_answer=bad", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	if !policy.captchaLocked(req, "203.0.113.10", "image", token) {
		t.Fatal("expected challenge token to be locked after max failures")
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
	expires := time.Now().Add(time.Minute).Unix()
	nonce := "test-nonce"
	answer := solveTestProof(nonce, 2)
	signature := policy.signChallenge(req, "203.0.113.10", nonce, expires)
	req = httptest.NewRequest(http.MethodGet, "/login?cw_nonce="+nonce+"&cw_expires="+strconv.FormatInt(expires, 10)+"&cw_sig="+signature+"&cw_pow="+answer, nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rr := httptest.NewRecorder()

	policy.ServeChallenge(rr, req, "203.0.113.10")
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect after valid proof, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Result().Cookies(); len(got) != 1 || got[0].Name != "cw_clearance" {
		t.Fatalf("expected clearance cookie, got %+v", got)
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
	})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	challenge, err := policy.newAltchaChallenge(req, "203.0.113.10")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	payload := solveAltchaPayload(t, challenge)
	req = httptest.NewRequest(http.MethodGet, "/login?cw_altcha="+payload, nil)
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
	if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), "cw_clearance_queue") {
		t.Fatalf("expected waiting room page, status=%d body=%s", rr.Code, rr.Body.String())
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
