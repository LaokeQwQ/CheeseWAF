package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func newPasskeyTestHandler(t *testing.T) (*Handler, *storage.SQLiteStore, passkey.Store) {
	t.Helper()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "passkey-handler.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	cfg := config.Default()
	cfg.Console.Login.Passkey = config.PasskeyConfig{
		Enabled:       true,
		RPDisplayName: "CheeseWAF",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}
	credentialStore := store.PasskeyStore()
	service, err := passkey.NewService(passkey.Config{
		RPDisplayName: "CheeseWAF",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, passkey.Options{
		Store:      credentialStore,
		SessionKey: bytes.Repeat([]byte{0x42}, passkey.MinSessionKeyLen),
	})
	if err != nil {
		t.Fatalf("new passkey service: %v", err)
	}
	h := New(Options{
		Config:       &cfg,
		Store:        store,
		Tokens:       middleware.NewTokenManager("passkey-handler-test-secret", time.Hour),
		Passkey:      service,
		PasskeyStore: credentialStore,
	})
	return h, store, credentialStore
}

func passkeyTestClaims(user *storage.User) *middleware.Claims {
	return &middleware.Claims{ID: "session-" + user.ID, Subject: user.ID, Username: user.Username, Role: user.Role, IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix()}
}

func passkeyTestRequest(method, target, body string, claims *middleware.Claims) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Content-Type", "application/json")
	if claims != nil {
		request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
	}
	return request
}

func decodePasskeyEnvelope(t *testing.T, recorder *httptest.ResponseRecorder) dto.Response {
	t.Helper()
	var envelope dto.Response
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	return envelope
}

func passkeyTestCredential(userID string, seed byte) *passkey.Credential {
	credentialID := bytes.Repeat([]byte{seed, 0x11, 0x22, 0x33}, 5)
	return &passkey.Credential{
		ID:           hex.EncodeToString(credentialID),
		UserID:       userID,
		CredentialID: credentialID,
		PublicKey:    []byte{0xa1, 0x01, 0x03, 0x26},
		Transports:   []string{"internal"},
		CreatedAt:    time.Now().UTC(),
		Name:         "Test Passkey",
	}
}

func TestPasskeyOptionsAndDisabledRoutes(t *testing.T) {
	cfg := config.Default()
	h := &Handler{Config: &cfg}

	recorder := httptest.NewRecorder()
	h.PasskeyOptions(recorder, httptest.NewRequest(http.MethodGet, "/api/auth/passkey/options", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("options status = %d", recorder.Code)
	}
	envelope := decodePasskeyEnvelope(t, recorder)
	data, ok := envelope.Data.(map[string]any)
	if !ok || data["enabled"] != false {
		t.Fatalf("disabled options data = %#v", envelope.Data)
	}

	recorder = httptest.NewRecorder()
	h.PasskeyLoginBegin(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/passkey/login/begin", `{"username":"reader"}`, nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled begin status = %d", recorder.Code)
	}
	if err := decodePasskeyEnvelope(t, recorder).Error; err == nil || err.Code != "PASSKEY_DISABLED" {
		t.Fatalf("disabled begin error = %#v", err)
	}
}

func TestPasskeyOptionsReportsRelyingParty(t *testing.T) {
	h, _, _ := newPasskeyTestHandler(t)
	recorder := httptest.NewRecorder()
	h.PasskeyOptions(recorder, httptest.NewRequest(http.MethodGet, "/api/auth/passkey/options", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("options status = %d", recorder.Code)
	}
	data, _ := decodePasskeyEnvelope(t, recorder).Data.(map[string]any)
	if data["enabled"] != true || data["rp_id"] != "example.com" {
		t.Fatalf("options data = %#v", data)
	}
	if _, leaked := data["origins"]; leaked {
		t.Fatalf("public options must not enumerate origin policy: %#v", data)
	}
}

func TestPasskeyLoginBeginUsesGenericInvalidCredentials(t *testing.T) {
	h, _, _ := newPasskeyTestHandler(t)
	createUserFixture(t, h.Store, "reader-id", "reader", "reader-password", "readonly")

	// Password login baseline for comparison.
	passwordRecorder := httptest.NewRecorder()
	h.Login(passwordRecorder, passkeyTestRequest(http.MethodPost, "/api/auth/login", `{"username":"reader","password":"wrong-password"}`, nil))
	if passwordRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("password baseline status = %d", passwordRecorder.Code)
	}
	passwordError := decodePasskeyEnvelope(t, passwordRecorder).Error
	if passwordError == nil || passwordError.Code != "INVALID_CREDENTIALS" {
		t.Fatalf("password baseline error = %#v", passwordError)
	}

	for _, username := range []string{"reader", "missing"} {
		recorder := httptest.NewRecorder()
		h.PasskeyLoginBegin(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/passkey/login/begin", `{"username":"`+username+`"}`, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s begin status = %d body=%s", username, recorder.Code, recorder.Body.String())
		}
		err := decodePasskeyEnvelope(t, recorder).Error
		if err == nil || err.Code != passwordError.Code || err.Message != passwordError.Message {
			t.Fatalf("%s begin error = %#v, want %#v", username, err, passwordError)
		}
	}

	recorder := httptest.NewRecorder()
	h.PasskeyLoginBegin(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/passkey/login/begin", `{"username":"bad name"}`, nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid username status = %d", recorder.Code)
	}
	if err := decodePasskeyEnvelope(t, recorder).Error; err == nil || err.Code != "USERNAME_INVALID" {
		t.Fatalf("invalid username error = %#v", err)
	}
}

func TestPasskeyLoginFinishRejectsIncompleteOrInvalidAssertions(t *testing.T) {
	h, _, _ := newPasskeyTestHandler(t)
	createUserFixture(t, h.Store, "reader-id", "reader", "reader-password", "readonly")

	for name, body := range map[string]string{
		"missing token":      `{"username":"reader","credential":{"id":"AAAA","type":"public-key","rawId":"AAAA","response":{}}}`,
		"missing credential": `{"username":"reader","session_token":"opaque"}`,
		"invalid token":      `{"username":"reader","session_token":"opaque","credential":{"id":"AAAA","type":"public-key","rawId":"AAAA","response":{}}}`,
	} {
		recorder := httptest.NewRecorder()
		h.PasskeyLoginFinish(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/passkey/login/finish", body, nil))
		if recorder.Code != http.StatusUnauthorized && recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d body=%s", name, recorder.Code, recorder.Body.String())
		}
		if cookies := recorder.Header().Values("Set-Cookie"); len(cookies) != 0 {
			t.Fatalf("%s issued session cookies: %v", name, cookies)
		}
		if name != "invalid token" && recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", name, recorder.Code)
		}
		if name == "invalid token" {
			if err := decodePasskeyEnvelope(t, recorder).Error; err == nil || err.Code != "INVALID_CREDENTIALS" {
				t.Fatalf("%s error = %#v", name, err)
			}
		}
	}
}

func TestPasskeyRegistrationAndCredentialManagementRequireAuthentication(t *testing.T) {
	h, _, _ := newPasskeyTestHandler(t)
	createUserFixture(t, h.Store, "reader-id", "reader", "reader-password", "readonly")

	unauthenticated := []struct {
		name   string
		method string
		target string
		body   string
		handle func(http.ResponseWriter, *http.Request)
	}{
		{"register begin", http.MethodPost, "/api/auth/passkey/register/begin", `{}`, h.PasskeyRegisterBegin},
		{"register finish", http.MethodPost, "/api/auth/passkey/register/finish", `{}`, h.PasskeyRegisterFinish},
		{"credentials", http.MethodGet, "/api/auth/passkey/credentials", "", h.PasskeyCredentials},
		{"delete", http.MethodDelete, "/api/auth/passkey/credentials/abc", "", h.PasskeyCredentialDelete},
	}
	for _, test := range unauthenticated {
		recorder := httptest.NewRecorder()
		test.handle(recorder, passkeyTestRequest(test.method, test.target, test.body, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want 401", test.name, recorder.Code)
		}
	}
}

func TestPasskeyCredentialListAndDeleteEnforceOwnership(t *testing.T) {
	h, store, credentialStore := newPasskeyTestHandler(t)
	createUserFixture(t, store, "alice-id", "alice", "alice-password", "readonly")
	createUserFixture(t, store, "bob-id", "bob", "bob-password", "readonly")
	alice, err := store.GetUserByUsername(context.Background(), "alice")
	if err != nil || alice == nil {
		t.Fatalf("alice fixture unavailable: user=%+v err=%v", alice, err)
	}

	aliceCredential := passkeyTestCredential("alice-id", 1)
	bobCredential := passkeyTestCredential("bob-id", 2)
	if err := credentialStore.Create(context.Background(), aliceCredential); err != nil {
		t.Fatalf("create alice credential: %v", err)
	}
	if err := credentialStore.Create(context.Background(), bobCredential); err != nil {
		t.Fatalf("create bob credential: %v", err)
	}

	recorder := httptest.NewRecorder()
	h.PasskeyCredentials(recorder, passkeyTestRequest(http.MethodGet, "/api/auth/passkey/credentials", "", passkeyTestClaims(alice)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	data, _ := decodePasskeyEnvelope(t, recorder).Data.(map[string]any)
	list, _ := data["credentials"].([]any)
	if len(list) != 1 {
		t.Fatalf("alice list = %#v, want one owned credential", data)
	}
	if first, _ := list[0].(map[string]any); first["id"] != aliceCredential.ID {
		t.Fatalf("alice list returned another account's credential: %#v", first)
	}

	routeRequest := func(id string) *http.Request {
		request := passkeyTestRequest(http.MethodDelete, "/api/auth/passkey/credentials/"+id, "", passkeyTestClaims(alice))
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("id", id)
		return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	}

	recorder = httptest.NewRecorder()
	h.PasskeyCredentialDelete(recorder, routeRequest(bobCredential.ID))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("delete other credential status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := credentialStore.GetByCredentialID(context.Background(), bobCredential.CredentialID); err != nil {
		t.Fatalf("other account's credential was deleted: %v", err)
	}

	recorder = httptest.NewRecorder()
	h.PasskeyCredentialDelete(recorder, routeRequest(aliceCredential.ID))
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete own credential status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := credentialStore.GetByCredentialID(context.Background(), aliceCredential.CredentialID); err == nil {
		t.Fatal("own credential still exists after delete")
	}
}

func TestPasskeyLoginDoesNotBypassTwoFactorPasswordLogin(t *testing.T) {
	h, store, _ := newPasskeyTestHandler(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("reader-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := store.CreateUser(context.Background(), &storage.User{
		ID:           "reader-id",
		Username:     "reader",
		PasswordHash: string(hash),
		Role:         "readonly",
		TwoFAEnabled: true,
		TwoFASecret:  "JBSWY3DPEHPK3PXP",
	}); err != nil {
		t.Fatalf("create two-factor user: %v", err)
	}

	recorder := httptest.NewRecorder()
	h.Login(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/login", `{"username":"reader","password":"reader-password"}`, nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("password login without TOTP status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := decodePasskeyEnvelope(t, recorder).Error; err == nil || err.Code != "TWO_FA_REQUIRED" {
		t.Fatalf("password login without TOTP error = %#v", err)
	}

	recorder = httptest.NewRecorder()
	h.PasskeyLoginFinish(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/passkey/login/finish",
		`{"username":"reader","session_token":"forged","credential":{"id":"AAAA","type":"public-key","rawId":"AAAA","response":{}}}`, nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("forged passkey finish status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if cookies := recorder.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("forged assertion issued session cookies: %v", cookies)
	}
}

func TestPasskeyLoginFailureIsAudited(t *testing.T) {
	h, _, _ := newPasskeyTestHandler(t)
	h.Auditor = middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))

	recorder := httptest.NewRecorder()
	h.PasskeyLoginBegin(recorder, passkeyTestRequest(http.MethodPost, "/api/auth/passkey/login/begin", `{"username":"missing"}`, nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user status = %d", recorder.Code)
	}
	entries, err := h.Auditor.Query(10)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(entries) != 1 || entries[0].Target != "auth.passkey.login" || entries[0].Status != http.StatusUnauthorized {
		t.Fatalf("passkey failure audit entries = %+v", entries)
	}
}
