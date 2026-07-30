package middleware

import (
	"net/http"
	"strings"
)

// CSRFMiddleware enforces double-submit CSRF for cookie-authenticated browser sessions.
// Management API Bearer tokens (cwapi_*) and pure Authorization Bearer sessions without
// a session cookie are exempt. Safe methods are always allowed.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || next == nil {
			return
		}
		if !RequiresCSRF(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		// Machine tokens never need browser CSRF.
		if raw := bearerToken(r); strings.HasPrefix(raw, ManagementAPITokenPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		// Cookie session requires double-submit CSRF.
		if SessionFromCookie(r) {
			if !ValidCSRFDoubleSubmit(r) {
				writeAPIError(w, http.StatusForbidden, "CSRF_INVALID", "csrf token missing or invalid")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
