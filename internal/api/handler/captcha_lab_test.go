package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	protectionbot "github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
)

func TestCaptchaLabChallengeCapacityReturnsServiceUnavailable(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	h := &Handler{Config: captchaLabTestConfig(time.Minute), Secret: "captcha-lab-test", now: func() time.Time { return now }}
	h.behaviorCAPTCHAState = protectionbot.NewChallengeStore(protectionbot.ChallengeStoreConfig{
		Capacity: 1,
		Now:      func() time.Time { return now },
	})
	h.behaviorCAPTCHAOnce.Do(func() {})
	if err := h.behaviorCAPTCHAState.Add("occupied", now.Add(time.Minute)); err != nil {
		t.Fatalf("prefill challenge store: %v", err)
	}

	response := callCaptchaLabHandler(t, h.IssueCaptchaLabChallenge, `{"type":"pow"}`)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d, want 503: %s", response.Code, response.Body.String())
	}
}

func TestCaptchaLabExpiredChallengeReturnsGone(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	h := &Handler{Config: captchaLabTestConfig(time.Second), Secret: "captcha-lab-test", now: func() time.Time { return now }}

	issued := callCaptchaLabHandler(t, h.IssueCaptchaLabChallenge, `{"type":"pow"}`)
	if issued.Code != http.StatusOK {
		t.Fatalf("issue status = %d: %s", issued.Code, issued.Body.String())
	}
	var envelope struct {
		Data captcha.BehaviorChallenge `json:"data"`
	}
	if err := json.NewDecoder(issued.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode issued challenge: %v", err)
	}
	now = now.Add(2 * time.Second)
	body, err := json.Marshal(captcha.BehaviorResponse{Token: envelope.Data.Token})
	if err != nil {
		t.Fatalf("marshal expired response: %v", err)
	}
	verified := callCaptchaLabHandler(t, h.VerifyCaptchaLabChallenge, string(body))
	if verified.Code != http.StatusGone {
		t.Fatalf("expired status = %d, want 410: %s", verified.Code, verified.Body.String())
	}
}

func TestCaptchaLabIncorrectAnswerIsNormalOneTimeOutcome(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	h := &Handler{Config: captchaLabTestConfig(time.Minute), Secret: "captcha-lab-test", now: func() time.Time { return now }}

	issued := callCaptchaLabHandler(t, h.IssueCaptchaLabChallenge, `{"type":"text_click"}`)
	if issued.Code != http.StatusOK {
		t.Fatalf(`issue status = %d: %s`, issued.Code, issued.Body.String())
	}
	var envelope struct {
		Data captcha.BehaviorChallenge `json:"data"`
	}
	if err := json.NewDecoder(issued.Body).Decode(&envelope); err != nil {
		t.Fatalf(`decode issued challenge: %v`, err)
	}
	body, err := json.Marshal(captcha.BehaviorResponse{
		Token:      envelope.Data.Token,
		Point:      &captcha.BehaviorPoint{X: 0, Y: 0},
		DurationMS: 500,
	})
	if err != nil {
		t.Fatalf(`marshal response: %v`, err)
	}
	verified := callCaptchaLabHandler(t, h.VerifyCaptchaLabChallenge, string(body))
	if verified.Code != http.StatusOK {
		t.Fatalf(`incorrect answer status = %d, want 200: %s`, verified.Code, verified.Body.String())
	}
	var result struct {
		Data captcha.BehaviorResult `json:"data"`
	}
	if err := json.NewDecoder(verified.Body).Decode(&result); err != nil {
		t.Fatalf(`decode verify result: %v`, err)
	}
	if result.Data.Valid || result.Data.Reason != "" {
		t.Fatalf(`unexpected public failure result: %+v`, result.Data)
	}
	replayed := callCaptchaLabHandler(t, h.VerifyCaptchaLabChallenge, string(body))
	if replayed.Code != http.StatusGone {
		t.Fatalf(`replay status = %d, want 410: %s`, replayed.Code, replayed.Body.String())
	}
}

func captchaLabTestConfig(ttl time.Duration) *config.Config {
	cfg := config.Default()
	cfg.Protection.Bot.CAPTCHAChallengeTTL = ttl
	return &cfg
}

func callCaptchaLabHandler(t *testing.T, fn http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/captcha/lab", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	claims := &middleware.Claims{Subject: "admin-id", Username: "admin", Role: "admin"}
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	fn(recorder, request)
	return recorder
}
