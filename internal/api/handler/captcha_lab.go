package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	protectionbot "github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
)

type botChallengeStore = protectionbot.ChallengeStore

type captchaLabIssuePayload struct {
	Type string `json:"type"`
}

func (h *Handler) IssueCaptchaLabChallenge(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireCaptchaLabAdmin(w, r)
	if !ok {
		return
	}
	var req captchaLabIssuePayload
	if !decode(w, r, &req) {
		return
	}
	kind, version, ok := captchaLabBehaviorType(req.Type)
	if !ok {
		writeError(w, http.StatusBadRequest, "CAPTCHA_TYPE_UNSUPPORTED", "unsupported behavior CAPTCHA type")
		return
	}
	challenge, err := captcha.IssueBehaviorChallenge(h.captchaLabOptions(claims, kind, version))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CAPTCHA_ISSUE_FAILED", "failed to issue behavior CAPTCHA")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, challenge.ExpiresAt)
	if err != nil || h.captchaLabState().Add(captchaLabTokenID(challenge.Token), expiresAt) != nil {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_STATE_UNAVAILABLE", "behavior CAPTCHA state is unavailable")
		return
	}
	writeData(w, challenge)
}

func (h *Handler) VerifyCaptchaLabChallenge(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireCaptchaLabAdmin(w, r)
	if !ok {
		return
	}
	var response captcha.BehaviorResponse
	if !decode(w, r, &response) {
		return
	}
	token := strings.TrimSpace(response.Token)
	if token == "" {
		writeError(w, http.StatusBadRequest, "CAPTCHA_TOKEN_REQUIRED", "behavior CAPTCHA token is required")
		return
	}
	tokenID := captchaLabTokenID(token)
	// Reject unknown/expired tokens without crypto work. Consume only after shape checks.
	if status := h.captchaLabState().Status(tokenID); status != protectionbot.ChallengePending {
		writeError(w, http.StatusGone, "CAPTCHA_ALREADY_USED", "behavior CAPTCHA is expired or already used")
		return
	}
	// Pin verification to the issued challenge type carried in the sealed token
	// (BehaviorRandom only skips client-side type selection, not token binding).
	result := captcha.VerifyBehaviorChallenge(h.captchaLabOptions(claims, captcha.BehaviorRandom, 3), response)
	// Burn the jti after a well-formed verification attempt (success or wrong answer)
	// so concurrent retries cannot brute-force the same token.
	if _, consumed := h.captchaLabState().Consume(tokenID); !consumed {
		writeError(w, http.StatusGone, "CAPTCHA_ALREADY_USED", "behavior CAPTCHA is expired or already used")
		return
	}
	if !result.Valid {
		result.Reason = result.Reason[:0]
		writeData(w, result)
		return
	}
	writeData(w, result)
}

func (h *Handler) captchaLabOptions(claims *middleware.Claims, kind captcha.BehaviorType, version int) captcha.BehaviorOptions {
	ttl := 2 * time.Minute
	if h != nil && h.Config != nil && h.Config.Protection.Bot.CAPTCHAChallengeTTL > 0 {
		ttl = h.Config.Protection.Bot.CAPTCHAChallengeTTL
	}
	return captcha.BehaviorOptions{
		Secret:         h.loginCaptchaSecret(),
		Purpose:        "admin-captcha-lab",
		ClientKey:      claims.Subject + "\n" + claims.Username,
		Path:           "/api/captcha/lab",
		Site:           "admin-console",
		TTL:            ttl,
		Type:           kind,
		Version:        version,
		Intensity:      3,
		Tolerance:      500,
		MinDuration:    120 * time.Millisecond,
		MaxDuration:    2 * time.Minute,
		MaxTrackPoints: 128,
		Now:            h.nowUTC,
	}
}

func (h *Handler) captchaLabState() *protectionbot.ChallengeStore {
	h.behaviorCAPTCHAOnce.Do(func() {
		h.behaviorCAPTCHAState = protectionbot.NewChallengeStore(protectionbot.ChallengeStoreConfig{
			Capacity:      4096,
			UsedRetention: 5 * time.Minute,
			Now:           h.nowUTC,
		})
	})
	return h.behaviorCAPTCHAState
}

func (h *Handler) requireCaptchaLabAdmin(w http.ResponseWriter, r *http.Request) (*middleware.Claims, bool) {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return nil, false
	}
	if claims.Role != "admin" || strings.TrimSpace(claims.Subject) == "" {
		writeError(w, http.StatusForbidden, "CAPTCHA_LAB_FORBIDDEN", "CAPTCHA Lab requires an administrator user session")
		return nil, false
	}
	return claims, true
}

func captchaLabBehaviorType(raw string) (captcha.BehaviorType, int, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "random":
		return captcha.BehaviorRandom, 3, true
	case "pow":
		return captcha.BehaviorPOW, 3, true
	case "curve_draw":
		return captcha.BehaviorCurveDraw, 3, true
	case "curve_slider":
		return captcha.BehaviorCurveSlider, 1, true
	case "curve_slider_v2":
		return captcha.BehaviorCurveSlider, 2, true
	case "curve_slider_v3":
		return captcha.BehaviorCurveSlider, 3, true
	case "shape_slider", "slider_v2":
		return captcha.BehaviorShapeSlider, 2, true
	case "rotate":
		return captcha.BehaviorRotate, 3, true
	case "restore_slider":
		return captcha.BehaviorRestoreSlider, 3, true
	case "angle":
		return captcha.BehaviorAngle, 3, true
	case "scratch":
		return captcha.BehaviorScratch, 3, true
	case "text_click":
		return captcha.BehaviorTextClick, 3, true
	case "icon_click":
		return captcha.BehaviorIconClick, 3, true
	default:
		return "", 0, false
	}
}

func captchaLabTokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
