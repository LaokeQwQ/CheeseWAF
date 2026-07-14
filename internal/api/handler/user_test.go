package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateUserRejectsPermissionExpressionRole(t *testing.T) {
	handler, _ := newUserTestHandler(t)

	for _, role := range []string{"*", "read:*", "write:system", "read:logs write:system"} {
		t.Run(role, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader([]byte(`{"username":"next","password":"correct-horse-battery","role":"`+role+`"}`)))
			handler.CreateUser(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected invalid role to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "ROLE_INVALID") {
				t.Fatalf("expected ROLE_INVALID response, body=%s", recorder.Body.String())
			}
		})
	}
}

func TestUpdateUserRejectsPermissionExpressionRoleWithoutMutation(t *testing.T) {
	handler, store := newUserTestHandler(t)

	router := chi.NewRouter()
	router.Put("/users/{id}", handler.UpdateUser)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/users/reader-id", bytes.NewReader([]byte(`{"role":"*"}`)))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid role to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	for _, user := range users {
		if user.ID == "reader-id" && user.Role != "readonly" {
			t.Fatalf("invalid role update mutated user: %+v", user)
		}
	}
}

func TestCreateUserAllowsConfiguredCustomRole(t *testing.T) {
	handler, store := newUserTestHandler(t)
	handler.Config.APISec.Permissions["operator"] = []string{"read:logs", "write:rules"}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader([]byte(`{"username":"operator","password":"correct-horse-battery","role":"operator"}`)))
	request = withUserClaims(request, "admin-id", "admin", "admin")
	handler.CreateUser(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected configured custom role to be accepted, got %d: %s", recorder.Code, recorder.Body.String())
	}
	user, err := store.GetUserByUsername(context.Background(), "operator")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if user == nil || user.Role != "operator" {
		t.Fatalf("custom role was not persisted: %+v", user)
	}
}

func TestCreateUserRejectsAdminRoleWithoutAdminCaller(t *testing.T) {
	handler, _ := newUserTestHandler(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader([]byte(`{"username":"next-admin","password":"correct-horse-battery","role":"admin"}`)))
	handler.CreateUser(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected non-admin admin grant to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateUserRejectsAdminGrantByWriteUsersRole(t *testing.T) {
	handler, store := newUserTestHandler(t)
	handler.Config.APISec.Permissions["operator"] = []string{"write:users"}

	router := chi.NewRouter()
	router.Put("/users/{id}", handler.UpdateUser)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/users/reader-id", bytes.NewReader([]byte(`{"role":"admin"}`)))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "operator-id", Username: "operator", Role: "operator"}))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected admin grant to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	user, err := store.GetUserByUsername(context.Background(), "reader")
	if err != nil {
		t.Fatalf("get reader: %v", err)
	}
	if user == nil || user.Role != "readonly" {
		t.Fatalf("admin grant mutated reader: %+v", user)
	}
}

func TestUpdateUserRejectsDemotingLastAdmin(t *testing.T) {
	handler, store := newUserTestHandler(t)
	createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")

	router := chi.NewRouter()
	router.Put("/users/{id}", handler.UpdateUser)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/users/admin-id", bytes.NewReader([]byte(`{"role":"readonly"}`)))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", Username: "admin", Role: "admin"}))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected last admin demotion to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	user, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	if user == nil || user.Role != "admin" {
		t.Fatalf("last admin was demoted: %+v", user)
	}
}

func TestWriteUsersRoleCannotModifyAdminAccount(t *testing.T) {
	handler, store := newUserTestHandler(t)
	handler.Config.APISec.Permissions["operator"] = []string{"write:users"}
	createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")

	router := chi.NewRouter()
	router.Put("/users/{id}", handler.UpdateUser)
	router.Post("/users/{id}/2fa/setup", handler.SetupUser2FA)
	claims := &middleware.Claims{Subject: "operator-id", Username: "operator", Role: "operator"}

	update := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/users/admin-id", bytes.NewReader([]byte(`{"password":"changed-password"}`)))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
	router.ServeHTTP(update, request)
	if update.Code != http.StatusForbidden {
		t.Fatalf("expected admin password update by write:users role to be rejected, got %d: %s", update.Code, update.Body.String())
	}

	setup := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/users/admin-id/2fa/setup", nil)
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
	router.ServeHTTP(setup, request)
	if setup.Code != http.StatusForbidden {
		t.Fatalf("expected write:users role to be unable to bind another user's 2fa, got %d: %s", setup.Code, setup.Body.String())
	}
}

func TestEnableUser2FARequiresPendingSecretForSameUser(t *testing.T) {
	handler, store := newUserTestHandler(t)
	now := fixedAuthTestTime()
	handler.now = func() time.Time { return now }
	createUserFixture(t, store, "other-id", "other", "other-password", "readonly")

	router := chi.NewRouter()
	router.Post("/users/{id}/2fa/setup", handler.SetupUser2FA)
	router.Post("/users/{id}/2fa/enable", handler.EnableUser2FA)

	setup := httptest.NewRecorder()
	router.ServeHTTP(setup, withUserClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/setup", nil), "reader-id", "reader", "readonly"))
	if setup.Code != http.StatusOK {
		t.Fatalf("expected setup ok, got %d: %s", setup.Code, setup.Body.String())
	}
	var setupEnvelope struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&setupEnvelope); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	code, err := hotp(setupEnvelope.Data.Secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}

	crossUser := httptest.NewRecorder()
	body := []byte(`{"secret":"` + setupEnvelope.Data.Secret + `","code":"` + code + `"}`)
	router.ServeHTTP(crossUser, withUserClaims(httptest.NewRequest(http.MethodPost, "/users/other-id/2fa/enable", bytes.NewReader(body)), "reader-id", "reader", "readonly"))
	if crossUser.Code != http.StatusForbidden {
		t.Fatalf("expected cross-user 2fa management to be forbidden, got %d: %s", crossUser.Code, crossUser.Body.String())
	}

	enable := httptest.NewRecorder()
	router.ServeHTTP(enable, withUserClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/enable", bytes.NewReader(body)), "reader-id", "reader", "readonly"))
	if enable.Code != http.StatusOK {
		t.Fatalf("expected same-user pending secret to enable 2fa, got %d: %s", enable.Code, enable.Body.String())
	}
}

func TestDisableUser2FARequiresCurrentPasswordAndCode(t *testing.T) {
	handler, store := newUserTestHandler(t)
	now := fixedAuthTestTime()
	handler.now = func() time.Time { return now }
	secret := "JBSWY3DPEHPK3PXP"
	user, err := store.GetUserByUsername(context.Background(), "reader")
	if err != nil {
		t.Fatalf("get reader: %v", err)
	}
	user.TwoFAEnabled = true
	user.TwoFASecret = secret
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("update reader 2fa: %v", err)
	}

	router := chi.NewRouter()
	router.Post("/users/{id}/2fa/disable", handler.DisableUser2FA)
	withReaderClaims := func(request *http.Request) *http.Request {
		return request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "reader-id", Username: "reader", Role: "readonly"}))
	}
	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, withReaderClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/disable", bytes.NewReader([]byte(`{}`)))))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing code to be rejected, got %d: %s", missing.Code, missing.Body.String())
	}

	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	wrongPassword := httptest.NewRecorder()
	router.ServeHTTP(wrongPassword, withReaderClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/disable", bytes.NewReader([]byte(`{"password":"wrong-password","code":"`+code+`"}`)))))
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("expected wrong password to be rejected, got %d: %s", wrongPassword.Code, wrongPassword.Body.String())
	}

	ok := httptest.NewRecorder()
	router.ServeHTTP(ok, withReaderClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/disable", bytes.NewReader([]byte(`{"password":"reader-password","code":"`+code+`"}`)))))
	if ok.Code != http.StatusOK {
		t.Fatalf("expected valid code to disable 2fa, got %d: %s", ok.Code, ok.Body.String())
	}
}

func TestRecoverUser2FARequiresAdministratorUserSession(t *testing.T) {
	tests := []struct {
		name   string
		claims *middleware.Claims
		status int
	}{
		{name: "non-admin user", claims: &middleware.Claims{Subject: "reader-id", ID: "reader-session", Username: "reader", Role: "readonly"}, status: http.StatusForbidden},
		{name: "api token", claims: &middleware.Claims{Subject: "api-token:token-id", ID: "token-id", Username: "automation", Role: "api_token"}, status: http.StatusForbidden},
		{name: "missing claims", status: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, store := newUserTestHandler(t)
			createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")
			router := chi.NewRouter()
			router.Post("/users/{id}/2fa/recover", handler.RecoverUser2FA)
			request := httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/recover", bytes.NewReader([]byte(`{"password":"admin-password","confirm_username":"reader"}`)))
			if test.claims != nil {
				request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, test.claims))
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("expected %d, got %d: %s", test.status, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRecoverUser2FAValidatesPasswordAndUsernameWithGenericError(t *testing.T) {
	handler, store := newUserTestHandler(t)
	createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")
	router := chi.NewRouter()
	router.Post("/users/{id}/2fa/recover", handler.RecoverUser2FA)
	claims := &middleware.Claims{Subject: "admin-id", ID: "admin-session", Username: "admin", Role: "admin"}

	for _, body := range []string{
		`{"password":"wrong-password","confirm_username":"reader"}`,
		`{"password":"admin-password","confirm_username":"wrong-user"}`,
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/recover", bytes.NewReader([]byte(body)))
		request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "INVALID_RECOVERY_CONFIRMATION") {
			t.Fatalf("expected generic recovery confirmation error, got %d: %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestRecoverUser2FAClearsStateAndRevokesTargetSessions(t *testing.T) {
	handler, store := newUserTestHandler(t)
	createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")
	target, err := store.GetUserByUsername(context.Background(), "reader")
	if err != nil {
		t.Fatalf("get target: %v", err)
	}
	target.TwoFAEnabled = true
	target.TwoFASecret = "JBSWY3DPEHPK3PXP"
	if err := store.UpdateUser(context.Background(), target); err != nil {
		t.Fatalf("enable target 2fa: %v", err)
	}
	handler.twoFATracker().storePending(target.ID, "PENDINGSECRET", time.Now().UTC().Add(time.Minute))
	now := time.Now().UTC()
	if err := store.CreateSession(context.Background(), &storage.Session{ID: "reader-session", UserID: target.ID, Username: target.Username, Role: target.Role, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("create target session: %v", err)
	}

	router := chi.NewRouter()
	router.Post("/users/{id}/2fa/recover", handler.RecoverUser2FA)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/recover", bytes.NewReader([]byte(`{"password":"admin-password","confirm_username":"reader"}`)))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "admin-session", Username: "admin", Role: "admin"}))
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected successful recovery, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("recovery response exposed secret material: %s", recorder.Body.String())
	}

	target, err = store.GetUserByUsername(context.Background(), "reader")
	if err != nil {
		t.Fatalf("reload target: %v", err)
	}
	if target.TwoFAEnabled || target.TwoFASecret != "" {
		t.Fatalf("target 2fa was not cleared: %+v", target)
	}
	handler.twoFATracker().mu.Lock()
	_, pending := handler.twoFATracker().pending[target.ID]
	handler.twoFATracker().mu.Unlock()
	if pending {
		t.Fatal("pending enrollment was not cleared")
	}
	active, err := store.IsSessionActive(context.Background(), "reader-session", target.ID, now)
	if err != nil {
		t.Fatalf("check target session: %v", err)
	}
	if active {
		t.Fatal("target session remained active after recovery")
	}
}

func TestEnableUser2FAInvalidCodeDoesNotConsumePendingSecret(t *testing.T) {
	handler, _ := newUserTestHandler(t)
	now := fixedAuthTestTime()
	handler.now = func() time.Time { return now }
	router := chi.NewRouter()
	router.Post("/users/{id}/2fa/setup", handler.SetupUser2FA)
	router.Post("/users/{id}/2fa/enable", handler.EnableUser2FA)

	setup := httptest.NewRecorder()
	router.ServeHTTP(setup, withUserClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/setup", nil), "reader-id", "reader", "readonly"))
	var envelope struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, withUserClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/enable", bytes.NewReader([]byte(`{"secret":"`+envelope.Data.Secret+`","code":"000000"}`))), "reader-id", "reader", "readonly"))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid code rejection, got %d: %s", invalid.Code, invalid.Body.String())
	}
	code, err := hotp(envelope.Data.Secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	valid := httptest.NewRecorder()
	router.ServeHTTP(valid, withUserClaims(httptest.NewRequest(http.MethodPost, "/users/reader-id/2fa/enable", bytes.NewReader([]byte(`{"secret":"`+envelope.Data.Secret+`","code":"`+code+`"}`))), "reader-id", "reader", "readonly"))
	if valid.Code != http.StatusOK {
		t.Fatalf("pending secret should survive an invalid code, got %d: %s", valid.Code, valid.Body.String())
	}
}

func TestEnableUser2FAInvalidCodesExhaustPendingSecret(t *testing.T) {
	handler, _ := newUserTestHandler(t)
	now := fixedAuthTestTime()
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	handler.twoFATracker().storePending("reader-id", secret, now.Add(twoFAPendingSecretTTL))
	for attempt := 0; attempt < twoFAPendingSecretMaxAttempts; attempt++ {
		result := handler.twoFATracker().verifyAndConsumePending("reader-id", secret, "000000", now)
		if result != twoFAPendingInvalidCode {
			t.Fatalf("attempt %d: expected invalid code, got %v", attempt+1, result)
		}
	}
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	if result := handler.twoFATracker().verifyAndConsumePending("reader-id", secret, code, now); result != twoFAPendingUnavailable {
		t.Fatalf("pending secret must expire after %d invalid attempts, got %v", twoFAPendingSecretMaxAttempts, result)
	}
}

func TestHandlersCanShareTwoFAState(t *testing.T) {
	first, _ := newUserTestHandler(t)
	second, _ := newUserTestHandler(t)
	state := NewAuthState()
	now := fixedAuthTestTime()
	ApplyAuthState(first, state)
	ApplyAuthState(second, state)
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	first.twoFATracker().storePending("reader-id", secret, now.Add(twoFAPendingSecretTTL))
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	if result := second.twoFATracker().verifyAndConsumePending("reader-id", secret, code, now); result != twoFAPendingConsumed {
		t.Fatalf("second handler did not observe shared pending state: %v", result)
	}
}

func fixedAuthTestTime() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

func withUserClaims(request *http.Request, id, username, role string) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: id, Username: username, Role: role}))
}

func TestConcurrentAdminDemotionsKeepOneAdmin(t *testing.T) {
	handler, store := newUserTestHandler(t)
	createUserFixture(t, store, "admin-one", "admin-one", "admin-one-password", "admin")
	createUserFixture(t, store, "admin-two", "admin-two", "admin-two-password", "admin")
	router := chi.NewRouter()
	router.Put("/users/{id}", handler.UpdateUser)

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"admin-one", "admin-two"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPut, "/users/"+id, bytes.NewReader([]byte(`{"role":"readonly"}`)))
			request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: id, Username: id, Role: "admin"}))
			router.ServeHTTP(recorder, request)
			statuses <- recorder.Code
		}(id)
	}
	close(start)
	wg.Wait()
	close(statuses)

	forbidden := 0
	for status := range statuses {
		if status == http.StatusForbidden {
			forbidden++
		}
	}
	if forbidden != 1 {
		t.Fatalf("expected exactly one concurrent demotion to be rejected, got %d", forbidden)
	}
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if countAdminUsers(users) != 1 {
		t.Fatalf("expected one admin to remain, got %d", countAdminUsers(users))
	}
}

func TestCreateUserRejectsTrailingJSONDocument(t *testing.T) {
	handler, store := newUserTestHandler(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader([]byte(`{"username":"operator","password":"correct-horse-battery","role":"operator"}{}`)))
	handler.CreateUser(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected trailing JSON to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "exactly one JSON document") {
		t.Fatalf("expected explicit trailing JSON error, body=%s", recorder.Body.String())
	}
	user, err := store.GetUserByUsername(context.Background(), "operator")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if user != nil {
		t.Fatalf("trailing JSON request should not create user: %+v", user)
	}
}

func newUserTestHandler(t *testing.T) (*Handler, *storage.SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("reader-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	createUserFixtureWithHash(t, store, "reader-id", "reader", string(hash), "readonly")
	cfg := config.Default()
	return New(Options{Config: &cfg, Store: store}), store
}

func createUserFixture(t *testing.T, store storage.Store, id, username, password, role string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	createUserFixtureWithHash(t, store, id, username, string(hash), role)
}

func createUserFixtureWithHash(t *testing.T, store storage.Store, id, username, passwordHash, role string) {
	t.Helper()
	if err := store.CreateUser(context.Background(), &storage.User{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
	}); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
}
