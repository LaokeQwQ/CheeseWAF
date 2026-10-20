package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestAuthenticationErrorsAreNotCacheable(t *testing.T) {
	w := httptest.NewRecorder()
	manager := NewTokenManager("test-secret", 0)
	manager.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated request reached endpoint") })).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/users", nil))
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("authentication error cache headers=%v", w.Header())
	}
}

func TestManagementAuditKeepsValidatedSourceAndSession(t *testing.T) {
	auditor := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	r := httptest.NewRequest(http.MethodPut, "/api/users/reader", nil)
	r.RemoteAddr = "127.0.0.1:4444"
	r.Header.Set("User-Agent", "test-console")
	r = r.WithContext(context.WithValue(r.Context(), UserContextKey, &Claims{ID: "session-id", Subject: "user-id", Username: "operator", Role: "operator"}))
	auditor.MiddlewareWithSource(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }), func(*http.Request) (string, string, string) { return "198.51.100.42", "127.0.0.1", "local_proxy" }).ServeHTTP(httptest.NewRecorder(), r)
	entries, err := auditor.Query(10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	entry := entries[0]
	if entry.RemoteIP != "198.51.100.42" || entry.PeerIP != "127.0.0.1" || entry.IPSource != "local_proxy" || entry.SessionID != "session-id" || entry.UserAgent != "test-console" {
		t.Fatalf("audit provenance=%+v", entry)
	}
}
