package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func TestCreateUserRejectsWhitespaceRoleWithoutCreatingAccount(t *testing.T) {
	for _, role := range []string{" admin ", "admin\t", "admin\n", "ad min", "ad\u00a0min", "ad\u200bmin", "admin\u2060", "admin\ufeff"} {
		t.Run(role, func(t *testing.T) {
			handler, store := newUserTestHandler(t)
			handler.Config.APISec.Permissions[role] = []string{"read:logs"}
			body, err := json.Marshal(userPayload{Username: "next-user", Password: "Correct-Horse-9x!", Role: role})
			if err != nil {
				t.Fatal(err)
			}
			request := withUserClaims(httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(body)), "admin-id", "admin", "admin")
			response := httptest.NewRecorder()

			handler.CreateUser(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "ROLE_INVALID") {
				t.Fatalf("expected role rejection, got %d: %s", response.Code, response.Body.String())
			}
			users, err := store.ListUsers(context.Background())
			if err != nil || len(users) != 1 {
				t.Fatalf("rejected role created an account: users=%+v err=%v", users, err)
			}
		})
	}
}

func TestUpdateUserRejectsWhitespaceAdminRoleWithoutChangingLastAdmin(t *testing.T) {
	for _, role := range []string{" admin ", "admin\t", "admin\n", "admin\u00a0"} {
		t.Run(role, func(t *testing.T) {
			handler, store := newUserTestHandler(t)
			createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")
			now := time.Now().UTC()
			admin, err := store.GetUserByID(context.Background(), "admin-id")
			if err != nil || admin == nil {
				t.Fatalf("get admin fixture: user=%+v err=%v", admin, err)
			}
			if err := store.CreateSession(context.Background(), &storage.Session{ID: "admin-session", UserID: admin.ID, Username: admin.Username, Role: admin.Role, CredentialEpoch: admin.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(userPayload{Role: role})
			if err != nil {
				t.Fatal(err)
			}
			request := withUserClaims(httptest.NewRequest(http.MethodPut, "/users/admin-id", bytes.NewReader(body)), "admin-id", "admin", "admin")
			response := httptest.NewRecorder()
			router := chi.NewRouter()
			router.Put("/users/{id}", handler.UpdateUser)

			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "ROLE_INVALID") {
				t.Fatalf("expected role rejection, got %d: %s", response.Code, response.Body.String())
			}
			user, err := store.GetUserByUsername(context.Background(), "admin")
			if err != nil || user == nil || user.Role != "admin" {
				t.Fatalf("rejected role changed the last administrator: user=%+v err=%v", user, err)
			}
			active, err := store.IsSessionActive(context.Background(), "admin-session", "admin-id", now.Add(time.Minute))
			if err != nil || !active {
				t.Fatalf("rejected role revoked the administrator session: active=%v err=%v", active, err)
			}
		})
	}
}
