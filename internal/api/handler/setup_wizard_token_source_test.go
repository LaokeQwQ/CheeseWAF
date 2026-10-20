package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
)

func TestSetupMutationReadsRotatedTokenSource(t *testing.T) {
	dataDir := t.TempDir()
	store := setup.NewTokenStore(dataDir)
	oldToken, err := store.Ensure("")
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	h := New(Options{
		Config:           &config.Config{Setup: config.SetupConfig{DataDir: dataDir}},
		SetupToken:       "startup-fallback-secret",
		SetupTokenSource: store,
	})

	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/setup", nil)
		req.Header.Set("X-CheeseWAF-Setup-Token", token)
		recorder := httptest.NewRecorder()
		if h.allowSetupMutation(recorder, req) {
			recorder.Code = http.StatusNoContent
		}
		return recorder
	}
	if response := request(oldToken); response.Code != http.StatusNoContent {
		t.Fatalf("old token before rotation returned status %d", response.Code)
	}

	newToken, err := store.Rotate()
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if response := request(oldToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("old token after rotation returned status %d, want 401", response.Code)
	}
	if response := request(newToken); response.Code != http.StatusNoContent {
		t.Fatalf("new token after rotation returned status %d, want 204", response.Code)
	}
	if response := request("startup-fallback-secret"); response.Code != http.StatusUnauthorized {
		t.Fatalf("startup token after rotation returned status %d, want 401", response.Code)
	}
	if response := request(" " + newToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("token with surrounding whitespace returned status %d, want 401", response.Code)
	}
}

func TestSetupMutationDoesNotFallbackWhenTokenSourceExpires(t *testing.T) {
	dataDir := t.TempDir()
	store := setup.NewTokenStore(dataDir)
	expiredToken, err := store.Ensure("")
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	h := New(Options{
		Config:           &config.Config{Setup: config.SetupConfig{DataDir: dataDir}},
		SetupToken:       "startup-fallback-secret",
		SetupTokenSource: store,
	})
	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/setup", nil)
		req.Header.Set("X-CheeseWAF-Setup-Token", token)
		recorder := httptest.NewRecorder()
		if h.allowSetupMutation(recorder, req) {
			recorder.Code = http.StatusNoContent
		}
		return recorder
	}

	expiredAt := time.Now().Add(-setup.SetupTokenTTL - time.Minute)
	if err := os.Chtimes(setup.TokenFilePath(dataDir), expiredAt, expiredAt); err != nil {
		t.Fatalf("expire token file: %v", err)
	}
	if got := store.Current(); got != "" {
		t.Fatalf("Current() for expired token = %q, want empty", got)
	}
	if response := request(expiredToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("expired token returned status %d, want 401", response.Code)
	}
	if response := request("startup-fallback-secret"); response.Code != http.StatusUnauthorized {
		t.Fatalf("startup fallback token returned status %d, want 401", response.Code)
	}
}
