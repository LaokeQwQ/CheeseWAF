package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestLogoutDoesNotClearCookiesWhenSessionRevocationFails(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "logout.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	h := &Handler{Store: store}
	claims := &middleware.Claims{ID: "session-id", Subject: "user-id", Username: "admin", Role: "admin"}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9443/api/auth/logout", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, claims))
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("revocation failure cleared client cookies: %v", got)
	}
}
