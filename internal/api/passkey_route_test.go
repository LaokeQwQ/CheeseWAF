package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestPasskeyRoutesArePublicOnlyForOptionsAndLogin(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "passkey-router.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	cfg := config.Default()
	cfg.APISec.Audit.Enabled = false
	cfg.CAPTCHAAssets.Local.Path = filepath.Join(t.TempDir(), "captcha-assets")
	cfg.Console.Login.Passkey = config.PasskeyConfig{
		Enabled:       true,
		RPDisplayName: "CheeseWAF",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}
	credentialStore := store.PasskeyStore()
	service, err := NewPasskeyService(cfg.Console.Login.Passkey, credentialStore, "router-passkey-test-secret")
	if err != nil {
		t.Fatalf("new passkey service: %v", err)
	}
	if service == nil {
		t.Fatal("enabled passkey configuration produced no service")
	}
	router := NewRouter(Options{
		Config:             &cfg,
		Store:              store,
		Secret:             "router-passkey-test-secret",
		AssistantApprovals: ai.NewApprovalStore(),
		Passkey:            service,
		PasskeyStore:       credentialStore,
	})

	options := perform(router, http.MethodGet, "/api/auth/passkey/options", "", nil)
	if options.Code != http.StatusOK {
		t.Fatalf("public options status = %d: %s", options.Code, options.Body.String())
	}
	var envelope dto.Response
	if err := json.Unmarshal(options.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	data, _ := envelope.Data.(map[string]any)
	if data["enabled"] != true || data["rp_id"] != "example.com" {
		t.Fatalf("options data = %#v", data)
	}

	for _, test := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/api/auth/passkey/login/begin", []byte(`{"username":"missing"}`)},
		{http.MethodPost, "/api/auth/passkey/login/finish", []byte(`{"username":"missing","session_token":"opaque","credential":{"id":"AAAA","type":"public-key","rawId":"AAAA","response":{}}}`)},
		{http.MethodPost, "/api/auth/passkey/register/begin", []byte(`{}`)},
		{http.MethodPost, "/api/auth/passkey/register/finish", []byte(`{}`)},
		{http.MethodGet, "/api/auth/passkey/credentials", nil},
		{http.MethodDelete, "/api/auth/passkey/credentials/example", nil},
	} {
		recorder := perform(router, test.method, test.path, "", test.body)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want 401: %s", test.method, test.path, recorder.Code, recorder.Body.String())
		}
	}
}
