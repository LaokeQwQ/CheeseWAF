package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCSRFMiddlewareRequiresDoubleSubmitForCookieSession(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := CSRFMiddleware(next)

	req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "jwt"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "abc"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing header: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "jwt"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "abc"})
	req.Header.Set(CSRFHeaderName, "abc")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid csrf: %d", rec.Code)
	}
}

func TestSessionTokenPrefersCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "from-cookie"})
	req.Header.Set("Authorization", "Bearer from-header")
	if got := SessionToken(req); got != "from-cookie" {
		t.Fatalf("got %q", got)
	}
}

func TestCookieSecureFollowsTLSAndForwardedProto(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/api/auth/login", nil)
	if CookieSecure(plain) {
		t.Fatal("plain HTTP must not set Secure cookies")
	}
	httpsReq := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:9443/api/auth/login", nil)
	httpsReq.TLS = &tls.ConnectionState{}
	if !CookieSecure(httpsReq) {
		t.Fatal("TLS requests must set Secure cookies")
	}
	proxied := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/api/auth/login", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https, http")
	if !CookieSecure(proxied) {
		t.Fatal("X-Forwarded-Proto=https must set Secure cookies")
	}
}

func TestWriteSessionCookiesOmitsSecureOnPlainHTTP(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9443/api/auth/login", nil)
	WriteSessionCookies(rec, req, "jwt", "csrf", time.Hour)
	got := rec.Result().Cookies()
	if len(got) < 2 {
		t.Fatalf("cookies = %d", len(got))
	}
	for _, c := range got {
		if c.Secure {
			t.Fatalf("%s unexpectedly Secure on HTTP", c.Name)
		}
	}
}

func TestCSRFExemptsManagementAPIToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := CSRFMiddleware(next)
	req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+ManagementAPITokenPrefix+"secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("mgmt token should skip csrf, got %d", rec.Code)
	}
}
