package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
)

func TestLoginForwardedIdentityUsesLastHeaderValue(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Add("X-Forwarded-For", "203.0.113.9")
	r.Header.Add("X-Forwarded-For", "198.51.100.42")
	if got := trustedLoginClientIP(r, "127.0.0.1", false); got != "198.51.100.42" {
		t.Fatalf("client-supplied header overrode appended source: got %q", got)
	}
}

func TestLoginCAPTCHADoesNotSkipMalformedForwarding(t *testing.T) {
	for _, xff := range []string{"invalid", "203.0.113.8, invalid", ""} {
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header["X-Forwarded-For"] = []string{xff}
		if loginCAPTCHASkippedForPeer(r, false) {
			t.Fatalf("forwarded request skipped CAPTCHA with header %q", xff)
		}
	}
}

func TestLoginRejectsOversizedBodyBeforeCredentialCheck(t *testing.T) {
	h, _ := newUserTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"reader","password":"wrong","padding":"`+strings.Repeat("x", 33<<10)+`"}`))
	r.RemoteAddr = "127.0.0.1:4444"
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized login body reached credentials: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLoginRejectsCrossSiteOriginBeforeCredentialCheck(t *testing.T) {
	h, _ := newUserTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"reader","password":"reader-password"}`))
	r.Host = "console.example"
	r.Header.Set("Origin", "https://evil.example")
	r.RemoteAddr = "198.51.100.10:4444"
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "LOGIN_ORIGIN_INVALID") {
		t.Fatalf("cross-site login was accepted: status=%d body=%s", w.Code, w.Body.String())
	}
}

type stalledLoginBody struct {
	started chan struct{}
	release chan struct{}
}

func (b *stalledLoginBody) Read([]byte) (int, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	return 0, io.EOF
}

func (*stalledLoginBody) Close() error { return nil }

func TestLoginLimitsConcurrentBodyReadsPerSource(t *testing.T) {
	cfg := config.Default()
	h := &Handler{Config: &cfg, LoginCAPTCHAState: newLoginCAPTCHAState()}
	release := make(chan struct{})
	done := make(chan struct{}, 4)
	t.Cleanup(func() {
		close(release)
		for i := 0; i < 4; i++ {
			<-done
		}
	})
	for i := 0; i < 4; i++ {
		body := &stalledLoginBody{started: make(chan struct{}, 1), release: release}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
		r.RemoteAddr = "198.51.100.10:4444"
		go func() { h.Login(httptest.NewRecorder(), r); done <- struct{}{} }()
		select {
		case <-body.started:
		case <-time.After(time.Second):
			t.Fatal("login did not start reading body")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":" invalid "}`))
	r.RemoteAddr = "198.51.100.10:5555"
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("same source exceeded slow-body budget: status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":" invalid "}`))
	r.RemoteAddr = "198.51.100.11:5555"
	w = httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("another source was locked out by stalled bodies: status=%d", w.Code)
	}
	if len(h.LoginCAPTCHAState.loginSlots) != 0 {
		t.Fatal("slow bodies occupied password verification slots")
	}
}

func TestLoginFailuresBehindLocalProxyDoNotLockOtherSources(t *testing.T) {
	h, _ := newUserTestHandler(t)
	for i := 0; i < loginRateLimitMaxFailures+2; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"reader","password":"wrong"}`))
		r.RemoteAddr = "127.0.0.1:4444"
		r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.10")
		w := httptest.NewRecorder()
		h.Login(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("CAPTCHA failure %d: %d", i, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.11")
	if !h.loginCAPTCHATracker().loginAttemptAllowed(loginRateLimitKeys(r, "reader", false), h.nowUTC()) {
		t.Fatal("shared reverse proxy locked another client")
	}
}

func TestWriteUsersCannotResetPrivilegedCustomRolePassword(t *testing.T) {
	h, store := newUserTestHandler(t)
	h.Config.APISec.Permissions["helpdesk"] = []string{"read:users", "write:users"}
	h.Config.APISec.Permissions["deployer"] = []string{"write:cluster", "manage:api_tokens"}
	createUserFixture(t, store, "deployer-id", "deployer", "original-password", "deployer")
	before, _ := store.GetUserByID(context.Background(), "deployer-id")
	r := withUserClaims(httptest.NewRequest(http.MethodPut, "/users/deployer-id", strings.NewReader(`{"password":"Correct-Horse-9x!"}`)), "helpdesk-id", "helpdesk", "helpdesk")
	w := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Put("/users/{id}", h.UpdateUser)
	router.ServeHTTP(w, r)
	after, _ := store.GetUserByID(context.Background(), "deployer-id")
	if w.Code != http.StatusForbidden || after.PasswordHash != before.PasswordHash {
		t.Fatalf("helpdesk reset privileged account: status=%d", w.Code)
	}
}

func TestHandlerConstructorsPersistConsumedTOTP(t *testing.T) {
	h, store := newUserTestHandler(t)
	now := time.Now().UTC()
	secret := "JBSWY3DPEHPK3PXP"
	code, _ := hotp(secret, now.Unix()/totpPeriod)
	if !h.twoFATracker().consumeTOTP("reader-id", secret, code, now) {
		t.Fatal("first TOTP rejected")
	}
	second := New(Options{Config: h.Config, Store: store})
	ApplyAuthState(second, NewAuthState())
	if second.twoFATracker().consumeTOTP("reader-id", secret, code, now) {
		t.Fatal("new handler with shared auth state replayed persistent TOTP")
	}
}

func TestEnabledTwoFACannotBeReenrolledFromSession(t *testing.T) {
	h, store := newUserTestHandler(t)
	user, _ := store.GetUserByID(context.Background(), "reader-id")
	user.TwoFAEnabled, user.TwoFASecret = true, "JBSWY3DPEHPK3PXP"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []http.HandlerFunc{h.SetupUser2FA, h.EnableUser2FA} {
		r := withUserClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id", strings.NewReader(`{}`)), "reader-id", "reader", "readonly")
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("id", "reader-id")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
		w := httptest.NewRecorder()
		operation(w, r)
		if w.Code != http.StatusConflict {
			t.Fatalf("existing factor reenrolled: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestAuthenticationAuditKeepsBothPeerAndSource(t *testing.T) {
	h, store := newUserTestHandler(t)
	h.Auditor = middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"reader","password":"reader-password"}`))
	r.RemoteAddr = "127.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.42")
	r.Header.Set("User-Agent", "test-console")
	user, _ := store.GetUserByID(context.Background(), "reader-id")
	h.auditAuthentication(r, user, "auth.login", "password")
	entries, err := h.Auditor.Query(10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit entries=%v err=%v", entries, err)
	}
	if entries[0].RemoteIP != "198.51.100.42" || !strings.Contains(entries[0].Message, "peer=127.0.0.1") || !strings.Contains(entries[0].Message, "test-console") {
		t.Fatalf("authentication audit lost provenance: %+v", entries[0])
	}
}

func TestAuditMiddlewareUsesValidatedProxySource(t *testing.T) {
	h, _ := newUserTestHandler(t)
	h.Auditor = middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	next := h.AuditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &middleware.Claims{ID: "session-id", Subject: "reader-id", Username: "reader", Role: "readonly"}
		*r = *r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, claims))
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.RemoteAddr = "127.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.42")
	r.Header.Set("User-Agent", "test-console")
	next.ServeHTTP(httptest.NewRecorder(), r)
	entries, err := h.Auditor.Query(10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	entry := entries[0]
	if entry.RemoteIP != "198.51.100.42" || entry.PeerIP != "127.0.0.1" || entry.IPSource != "local_proxy" || entry.SessionID != "session-id" {
		t.Fatalf("validated audit source missing: %+v", entry)
	}
}
