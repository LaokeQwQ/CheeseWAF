package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func (h *Handler) issueCapLoginCAPTCHA(w http.ResponseWriter, r *http.Request, login config.ConsoleLoginConfig) {
	capConfig := h.currentConfig().CAPTCHAProviders.Cap
	if _, err := newConfiguredCapVerifier(capConfig); err != nil {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_UNAVAILABLE", "captcha verification is not configured")
		return
	}
	owner, peer, ok := h.loginCaptchaQuotaIdentity(w, r)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	if loginCaptchaClientKey(r) == "" || owner == "" {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	clientKey := loginCaptchaClientKey(r) + "\n" + owner
	tracker := h.loginCAPTCHATracker()
	now := h.nowUTC()
	reservation, ok := tracker.reserveIssuance(owner, peer, 1, now)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	committed := false
	defer func() {
		if !committed {
			tracker.rollbackIssuance(reservation)
		}
	}()

	challengeID, err := newCapChallengeID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CAPTCHA_ERROR", "captcha challenge could not be created")
		return
	}
	proofKey := loginCAPTCHAFingerprint("cap", clientKey, challengeID)
	now = h.nowUTC()
	if !tracker.stageIssuance(reservation, []string{proofKey}, now.Add(login.CAPTCHA.TTL), now) {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_CAPACITY_REACHED", "captcha service is temporarily busy")
		return
	}
	response := map[string]any{
		"enabled":  true,
		"provider": "cap",
		"mode":     "cap",
		"cap": map[string]string{
			"challenge_id": challengeID,
			"api_endpoint": capConfig.APIEndpoint,
			"wasm_url":     capConfig.WASMURL,
			"hashwx_url":   capConfig.HashWXURL,
		},
	}
	if err := writeDataResult(w, response); err != nil {
		return
	}
	if !tracker.finalizeIssuance(reservation) {
		return
	}
	committed = true
}

func (h *Handler) verifyLoginCapProof(r *http.Request, login config.LoginCAPTCHAConfig, payload *dto.CAPTCHAPayload) (bool, error) {
	if h == nil || r == nil || payload == nil || !login.Enabled ||
		!strings.EqualFold(strings.TrimSpace(payload.Provider), "cap") ||
		strings.TrimSpace(payload.ChallengeID) == "" || strings.TrimSpace(payload.Token) == "" ||
		!loginCAPTCHAPayloadSizeAllowed(payload) {
		return false, nil
	}
	clientKey, ok := h.loginCaptchaBoundClientKey(r)
	if !ok {
		return false, nil
	}
	proofKey := loginCAPTCHAFingerprint("cap", clientKey, payload.ChallengeID)
	proofKeys := []string{proofKey}
	tracker := h.loginCAPTCHATracker()
	if !tracker.reserveProofs(proofKeys, h.nowUTC()) {
		return false, nil
	}
	verified := false
	defer func() { tracker.finishProofs(proofKeys, verified, h.nowUTC()) }()

	capConfig := h.currentConfig().CAPTCHAProviders.Cap
	verifier, err := newConfiguredCapVerifier(capConfig)
	if err != nil {
		return false, err
	}
	verified, err = verifier.VerifyForPeer(r.Context(), payload.Token, socketPeerIP(r))
	if err != nil {
		return false, err
	}
	return verified, nil
}

func newConfiguredCapVerifier(cfg config.CapStandaloneConfig) (*captcha.CapVerifier, error) {
	return captcha.NewCapVerifierFromFile(cfg.SiteVerifyEndpoint(), cfg.SecretFile, cfg.Timeout)
}

// Runtime readiness belongs at activation boundaries, not structural config
// validation. A stale optional provider must not block unrelated config writes
// or prevent disabling a broken login integration.
func validateCapLoginReadiness(previous, candidate *config.Config) error {
	if candidate == nil {
		return fmt.Errorf("configuration is unavailable")
	}
	login := candidate.Console.Login.CAPTCHA
	if !login.Enabled || loginCaptchaProvider(login) != "cap" {
		return nil
	}
	if previous != nil && reflect.DeepEqual(previous.Console.Login.CAPTCHA, login) &&
		reflect.DeepEqual(previous.CAPTCHAProviders, candidate.CAPTCHAProviders) {
		return nil
	}
	if _, err := newConfiguredCapVerifier(candidate.CAPTCHAProviders.Cap); err != nil {
		return fmt.Errorf("console login CAPTCHA provider is invalid: %w", err)
	}
	return nil
}

func newCapChallengeID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
