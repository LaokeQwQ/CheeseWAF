package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"time"
)

// Browser session cookie names (HttpOnly JWT + readable CSRF double-submit).
const (
	SessionCookieName       = "cheesewaf_session"
	CSRFCookieName          = "cheesewaf_csrf"
	SecureSessionCookieName = "__Host-cheesewaf_session"
	SecureCSRFCookieName    = "__Host-cheesewaf_csrf"
	CSRFHeaderName          = "X-CSRF-Token"
)

// SessionCookieMaxAge mirrors default admin session TTL (24h) when unset.
const SessionCookieMaxAge = 24 * time.Hour

// SessionToken extracts the browser session JWT from the HttpOnly cookie, or
// falls back to Authorization Bearer (management API / migration bootstrap).
func SessionToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, name := range []string{SecureSessionCookieName, SessionCookieName} {
		if c, err := r.Cookie(name); err == nil {
			if v := strings.TrimSpace(c.Value); v != "" {
				return v
			}
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
	for _, name := range []string{SecureSessionCookieName, SessionCookieName} {
		if c, err := r.Cookie(name); err == nil && strings.TrimSpace(c.Value) != "" {
			return true
		}
	}
	return false
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
	for _, name := range []string{SecureCSRFCookieName, CSRFCookieName} {
		if c, err := r.Cookie(name); err == nil {
			if value := strings.TrimSpace(c.Value); value != "" {
				return value
			}
		}
	}
	return ""
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

// CookieSecure is true for TLS requests, or for HTTPS declared by a trusted
// reverse proxy. X-Forwarded-Proto is only trusted when the socket peer is
// loopback or a private network (RFC1918 / IPv6 ULA); public peers must not
// be able to flip Secure on by supplying a header.
func CookieSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !peerIsLoopbackOrPrivate(r) {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = strings.TrimSpace(proto[:i])
	}
	return proto == "https"
}

func peerIsLoopbackOrPrivate(r *http.Request) bool {
	if r == nil {
		return false
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// WriteCookie applies CookieSecure then writes Set-Cookie.
// Callers must not set Secure themselves; plain HTTP loopback has to omit it.
func WriteCookie(w http.ResponseWriter, r *http.Request, cookie *http.Cookie) {
	if w == nil || cookie == nil {
		return
	}
	cookie.Secure = CookieSecure(r)
	if v := cookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v)
	}
}

// WriteSessionCookies sets HttpOnly session JWT + non-HttpOnly CSRF cookies.
func WriteSessionCookies(w http.ResponseWriter, r *http.Request, sessionJWT, csrf string, maxAge time.Duration) {
	if w == nil {
		return
	}
	if maxAge <= 0 {
		maxAge = SessionCookieMaxAge
	}
	sessionName, csrfName := browserSessionCookieNames(r)
	WriteCookie(w, r, &http.Cookie{
		Name:     sessionName,
		Value:    sessionJWT,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	WriteCookie(w, r, &http.Cookie{
		Name:     csrfName,
		Value:    csrf,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: false, // JS must read for double-submit header
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookies expires session and CSRF cookies.
func ClearSessionCookies(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	names := []string{SessionCookieName, CSRFCookieName}
	if CookieSecure(r) {
		names = append(names, SecureSessionCookieName, SecureCSRFCookieName)
	}
	for _, name := range names {
		WriteCookie(w, r, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == SessionCookieName || name == SecureSessionCookieName,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

func browserSessionCookieNames(r *http.Request) (string, string) {
	if CookieSecure(r) {
		return SecureSessionCookieName, SecureCSRFCookieName
	}
	return SessionCookieName, CSRFCookieName
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
