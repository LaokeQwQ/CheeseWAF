package middleware

import (
	"bytes"
	"crypto/tls"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type countingReadCloser struct {
	reader    *bytes.Reader
	bytesRead int
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += n
	return n, err
}

func (*countingReadCloser) Close() error { return nil }

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

func TestCSRFMiddlewareBoundsFormTokenFallback(t *testing.T) {
	body := []byte("padding=" + strings.Repeat("a", 128<<10) + "&csrf_token=abc")
	for _, tc := range []struct {
		name          string
		contentLength int64
	}{
		{name: "declared length", contentLength: int64(len(body))},
		{name: "unknown length", contentLength: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trackedBody := &countingReadCloser{reader: bytes.NewReader(body)}
			req := httptest.NewRequest(http.MethodPost, "/api/x", nil)
			req.Body = trackedBody
			req.ContentLength = tc.contentLength
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "jwt"})
			req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "abc"})
			rec := httptest.NewRecorder()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})

			CSRFMiddleware(next).ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("oversized form status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			const maxExpectedRead = 64<<10 + 1
			if trackedBody.bytesRead > maxExpectedRead {
				t.Fatalf("CSRF fallback read %d bytes, want at most %d", trackedBody.bytesRead, maxExpectedRead)
			}
		})
	}
}

func TestCSRFMiddlewareAcceptsBoundedFormTokenFallback(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader("csrf_token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "jwt"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "abc"})
	rec := httptest.NewRecorder()

	CSRFMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("bounded form token status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestCSRFMiddlewareLargeMultipartUsesHeaderOnly(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", "large.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(bytes.Repeat([]byte("x"), 2<<20)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		header     string
		wantStatus int
		wantNext   bool
	}{
		{name: "valid header", header: "abc", wantStatus: http.StatusNoContent, wantNext: true},
		{name: "missing header", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trackedBody := &countingReadCloser{reader: bytes.NewReader(body.Bytes())}
			req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
			req.Body = trackedBody
			req.ContentLength = int64(body.Len())
			req.Header.Set("Content-Type", writer.FormDataContentType())
			if tc.header != "" {
				req.Header.Set(CSRFHeaderName, tc.header)
			}
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "jwt"})
			req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "abc"})
			rec := httptest.NewRecorder()
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})

			CSRFMiddleware(next).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if nextCalled != tc.wantNext {
				t.Fatalf("next called = %v, want %v", nextCalled, tc.wantNext)
			}
			if trackedBody.bytesRead != 0 {
				t.Fatalf("CSRF middleware read %d multipart bytes, want 0", trackedBody.bytesRead)
			}
		})
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
	proxied.RemoteAddr = "127.0.0.1:54321"
	proxied.Header.Set("X-Forwarded-Proto", "https, http")
	if !CookieSecure(proxied) {
		t.Fatal("X-Forwarded-Proto=https from a loopback peer must set Secure cookies")
	}
	privateProxied := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/api/auth/login", nil)
	privateProxied.RemoteAddr = "10.0.0.5:54321"
	privateProxied.Header.Set("X-Forwarded-Proto", "https")
	if !CookieSecure(privateProxied) {
		t.Fatal("X-Forwarded-Proto=https from a private peer must set Secure cookies")
	}
	publicProxied := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/api/auth/login", nil)
	publicProxied.RemoteAddr = "198.51.100.7:54321"
	publicProxied.Header.Set("X-Forwarded-Proto", "https")
	if CookieSecure(publicProxied) {
		t.Fatal("X-Forwarded-Proto=https must not be trusted from a public peer")
	}

}

func TestWriteCookieFollowsTLSAndForwardedProto(t *testing.T) {
	plain := httptest.NewRecorder()
	WriteCookie(plain, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/", nil), &http.Cookie{Name: "n", Value: "v", Path: "/"})
	got := plain.Result().Cookies()
	if len(got) != 1 || got[0].Secure {
		t.Fatalf("plain HTTP WriteCookie must omit Secure, got %+v", got)
	}
	httpsRec := httptest.NewRecorder()
	httpsReq := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:9443/", nil)
	httpsReq.TLS = &tls.ConnectionState{}
	WriteCookie(httpsRec, httpsReq, &http.Cookie{Name: "n", Value: "v", Path: "/"})
	got = httpsRec.Result().Cookies()
	if len(got) != 1 || !got[0].Secure {
		t.Fatalf("TLS WriteCookie must set Secure, got %+v", got)
	}
	proxiedRec := httptest.NewRecorder()
	proxiedReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9443/", nil)
	proxiedReq.RemoteAddr = "127.0.0.1:54321"
	proxiedReq.Header.Set("X-Forwarded-Proto", "https")
	WriteCookie(proxiedRec, proxiedReq, &http.Cookie{Name: "n", Value: "v", Path: "/"})
	got = proxiedRec.Result().Cookies()
	if len(got) != 1 || !got[0].Secure {
		t.Fatalf("forwarded-proto from loopback WriteCookie must set Secure, got %+v", got)
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

func TestWriteSessionCookiesUsesHostPrefixOnHTTPS(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://admin.example.test/api/auth/login", nil)
	req.TLS = &tls.ConnectionState{}
	WriteSessionCookies(rec, req, "jwt", "csrf", time.Hour)

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if !strings.HasPrefix(cookie.Name, "__Host-") || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatalf("HTTPS cookie does not satisfy __Host- requirements: %+v", cookie)
		}
	}
	req.AddCookie(cookies[0])
	if got := SessionToken(req); got != "jwt" {
		t.Fatalf("SessionToken() = %q, want secure cookie token", got)
	}
}

func TestClearSessionCookiesExpiresEveryCookieNameOnPlainHTTP(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9443/api/auth/logout", nil)

	ClearSessionCookies(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 4 {
		t.Fatalf("expired cookies = %d, want 4: %+v", len(cookies), cookies)
	}
	byName := make(map[string]*http.Cookie, len(cookies))
	for _, cookie := range cookies {
		byName[cookie.Name] = cookie
	}
	for _, name := range []string{SessionCookieName, CSRFCookieName, SecureSessionCookieName, SecureCSRFCookieName} {
		cookie := byName[name]
		if cookie == nil {
			t.Errorf("missing expired cookie %q", name)
			continue
		}
		if cookie.MaxAge >= 0 || cookie.Value != "" || cookie.Path != "/" {
			t.Errorf("cookie %q was not expired correctly: %+v", name, cookie)
		}
		wantSecure := strings.HasPrefix(name, "__Host-")
		if cookie.Secure != wantSecure {
			t.Errorf("cookie %q Secure = %v, want %v", name, cookie.Secure, wantSecure)
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
