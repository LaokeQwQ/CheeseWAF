package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
	if response := request(" " + newToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("token with surrounding whitespace returned status %d, want 401", response.Code)
	}
}
