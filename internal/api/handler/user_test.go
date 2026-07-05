package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
	if err := store.CreateUser(ctx, &storage.User{
		ID:           "reader-id",
		Username:     "reader",
		PasswordHash: string(hash),
		Role:         "readonly",
	}); err != nil {
		t.Fatalf("create reader: %v", err)
	}
	cfg := config.Default()
	return New(Options{Config: &cfg, Store: store}), store
}
