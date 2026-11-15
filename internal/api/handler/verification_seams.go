package handler

import (
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
)

// Verification seams for CHE-61. They expose existing unexported behaviour to
// black-box tests without changing production logic, and are safe to remove if
// the verification harness is dropped.

// NewLoginCAPTCHAStateForTest returns a fresh login CAPTCHA/rate-limit state.
func NewLoginCAPTCHAStateForTest() *AuthState { return NewAuthState() }

// AcquireLoginBody reserves one concurrent login body slot for a source.
func (s *AuthState) AcquireLoginBody(source string) bool {
	if s == nil || s.login == nil {
		return false
	}
	return s.login.acquireLoginBody(source)
}

// ReleaseLoginBody releases a previously reserved login body slot.
func (s *AuthState) ReleaseLoginBody(source string) {
	if s == nil || s.login == nil {
		return
	}
	s.login.releaseLoginBody(source)
}

// AcquireLoginSlot reserves one concurrent password-verification slot.
func (s *AuthState) AcquireLoginSlot() bool {
	if s == nil || s.login == nil {
		return false
	}
	return s.login.acquireLoginSlot()
}

// ReleaseLoginSlot releases a previously reserved verification slot.
func (s *AuthState) ReleaseLoginSlot() {
	if s == nil || s.login == nil {
		return
	}
	s.login.releaseLoginSlot()
}

// ForceLoginCAPTCHASecretForTest overrides the cached CAPTCHA signing secret so
// tests can exercise the "secret unavailable" fail-closed branch.
func ForceLoginCAPTCHASecretForTest(h *Handler, secret string) {
	if h == nil {
		return
	}
	h.loginCAPTCHASecretMu.Lock()
	h.loginCAPTCHASecret = secret
	h.loginCAPTCHASecretMu.Unlock()
}

// VerifyLoginCAPTCHAForTest exposes the login CAPTCHA decision.
func (h *Handler) VerifyLoginCAPTCHAForTest(r *http.Request, payload *dto.CAPTCHAPayload) bool {
	return h.verifyLoginCAPTCHA(r, payload)
}
