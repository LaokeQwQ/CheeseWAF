package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// Browser session cookie names (HttpOnly JWT + readable CSRF double-submit).
const (
	SessionCookieName = "cheesewaf_session"
	CSRFCookieName    = "cheesewaf_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// SessionCookieMaxAge mirrors default admin session TTL (24h) when unset.
const SessionCookieMaxAge = 24 * time.Hour

// SessionToken extracts the browser session JWT from the HttpOnly cookie, or
// falls back to Authorization Bearer (management API / migration bootstrap).
func SessionToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if c, err := r.Cookie(SessionCookieName); err == nil {
		if v := strings.TrimSpace(c.Value); v != "" {
			return v
		}
	}
	return bearerToken(r)
}

// SessionFromCookie reports whether the request authenticated via the session cookie
// (as opposed to an Authorization Bearer header).
func SessionFromCookie(r *http.Request) bool {
	if r == nil {
		return false
	}
	c, err := r.Cookie(SessionCookieName)
	return err == nil && strings.TrimSpace(c.Value) != ""
}

// CSRFTokenFromRequest returns the CSRF token from the double-submit header or form.
func CSRFTokenFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get(CSRFHeaderName)); v != "" {
		return v
	}
	if err := r.ParseForm(); err == nil {
		if v := strings.TrimSpace(r.Form.Get("csrf_token")); v != "" {
			return v
		}
	}
	return ""
}

// CSRFTokenFromCookie returns the CSRF cookie value (readable by JS).
func CSRFTokenFromCookie(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

// ValidCSRFDoubleSubmit checks cookie CSRF matches header/form CSRF.
func ValidCSRFDoubleSubmit(r *http.Request) bool {
	cookie := CSRFTokenFromCookie(r)
	header := CSRFTokenFromRequest(r)
	if cookie == "" || header == "" {
		return false
	}
	// Constant-time compare for equal-length tokens.
	if len(cookie) != len(header) {
		return false
	}
	var v byte
	for i := 0; i < len(cookie); i++ {
		v |= cookie[i] ^ header[i]
	}
	return v == 0
}

// NewCSRFToken generates a random CSRF token for double-submit.
func NewCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// WriteSessionCookies sets HttpOnly session JWT + non-HttpOnly CSRF cookies.
// Secure is always true (CodeQL go/cookie-secure-not-set): admin console is
// expected behind HTTPS or TLS-terminated reverse proxy.
func WriteSessionCookies(w http.ResponseWriter, r *http.Request, sessionJWT, csrf string, maxAge time.Duration) {
	if w == nil {
		return
	}
	if maxAge <= 0 {
		maxAge = SessionCookieMaxAge
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionJWT,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrf,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: false, // JS must read for double-submit header
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookies expires session and CSRF cookies.
func ClearSessionCookies(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	for _, name := range []string{SessionCookieName, CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == SessionCookieName,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// RequiresCSRF reports whether the method mutates state and needs CSRF for cookie sessions.
func RequiresCSRF(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
