package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestPasskeyRebuildInvalidatesPreviousChallenge(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "passkey.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := config.PasskeyConfig{Enabled: true, RPDisplayName: "Original", RPID: "example.com", RPOrigins: []string{"https://example.com"}}
	first, err := NewPasskeyService(cfg, store.PasskeyStore(), "test-auth-secret")
	if err != nil {
		t.Fatal(err)
	}
	user := passkey.User{ID: "user1", Name: "user1", DisplayName: "User"}
	_, token, err := first.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RPDisplayName = "Updated"
	next, err := NewPasskeyService(cfg, store.PasskeyStore(), "test-auth-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = next.FinishRegistration(context.Background(), user, token, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
	if !errors.Is(err, passkey.ErrInvalidSessionToken) {
		t.Fatalf("previous challenge survived rebuild: %v", err)
	}
}
