package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
)

func TestUnauthenticatedLoginFailureDoesNotWriteManagementAudit(t *testing.T) {
	h, _ := newUserTestHandler(t)
	h.Auditor = middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	h.Tokens = middleware.NewTokenManager("test-session-secret", time.Hour)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"reader","password":"wrong-password"}`))
	r.RemoteAddr = "127.0.0.1:9443"
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login response status=%d body=%s", w.Code, w.Body.String())
	}
	entries, err := h.Auditor.Query(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unauthenticated login failure reached management audit: %+v", entries)
	}
}

func TestSuccessfulAuthenticationAuditIsRecorded(t *testing.T) {
	h, store := newUserTestHandler(t)
	h.Auditor = middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	h.Tokens = middleware.NewTokenManager("test-session-secret", time.Hour)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"reader","password":"reader-password"}`))
	r.RemoteAddr = "127.0.0.1:9443"
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login response status=%d body=%s", w.Code, w.Body.String())
	}
	user, err := store.GetUserByUsername(context.Background(), "reader")
	if err != nil || user == nil {
		t.Fatalf("reader fixture unavailable: user=%+v err=%v", user, err)
	}
	entries, err := h.Auditor.Query(10)
	if err != nil || len(entries) != 1 || entries[0].Target != "auth.login" || entries[0].User != user.Username {
		t.Fatalf("successful login audit entries=%+v err=%v", entries, err)
	}
}
