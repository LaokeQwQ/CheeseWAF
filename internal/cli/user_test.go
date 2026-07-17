package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestChangeUserPasswordUpdatesHashAndDisables2FA(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	user := seedPasswordTestUser(t, store, "admin", "old-password-123")
	user.TwoFAEnabled = true
	user.TwoFASecret = "SECRET"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("enable test 2fa: %v", err)
	}

	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "new-password-123!",
	}); err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}

	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-password-123!")) != nil {
		t.Fatal("updated password hash does not match new password")
	}
	if updated.TwoFAEnabled || updated.TwoFASecret != "" {
		t.Fatalf("password reset should disable 2FA, got enabled=%v secret=%q", updated.TwoFAEnabled, updated.TwoFASecret)
	}
}

func TestChangeUserPasswordFromStdin(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	seedPasswordTestUser(t, store, "admin", "old-password-123")

	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		PasswordStdin: true,
		Input:         bytes.NewBufferString("stdin-password-123!\n"),
	}); err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}

	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("stdin-password-123!")) != nil {
		t.Fatal("updated password hash does not match stdin password")
	}
}

func TestChangeUserPasswordGenerate(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	seedPasswordTestUser(t, store, "admin", "old-password-123")

	generated, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{Generate: true})
	if err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}
	if len(generated) < 16 || !passwordHasClasses(generated) {
		t.Fatalf("generated password is not strong enough: %q", generated)
	}
	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte(generated)) != nil {
		t.Fatal("updated password hash does not match generated password")
	}
}

func TestChangeUserPasswordValidation(t *testing.T) {
	t.Parallel()

	_, sqlitePath := userPasswordTestStore(t)
	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "short",
	}); err == nil || !strings.Contains(err.Error(), "at least 10") {
		t.Fatalf("expected short password validation error, got %v", err)
	}
	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "valid-password-123",
		Generate: true,
	}); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected source validation error, got %v", err)
	}
}

func TestRenameUserUpdatesUsernameAndRevokesSessions(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	user := seedPasswordTestUser(t, store, "admin", "old-password-123")
	now := time.Now().UTC()
	session := &storage.Session{
		ID:        "session-1",
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	renamed, err := renameUser(context.Background(), sqlitePath, "admin", "Cheese")
	if err != nil {
		t.Fatalf("renameUser() error = %v", err)
	}
	if renamed.ID != user.ID || renamed.Username != "Cheese" {
		t.Fatalf("unexpected renamed user: %+v", renamed)
	}
	oldUser, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get old user: %v", err)
	}
	if oldUser != nil {
		t.Fatalf("old username should not resolve, got %+v", oldUser)
	}
	newUser, err := store.GetUserByUsername(context.Background(), "Cheese")
	if err != nil {
		t.Fatalf("get new user: %v", err)
	}
	if newUser == nil || newUser.ID != user.ID {
		t.Fatalf("new username did not resolve original user: %+v", newUser)
	}
	active, err := store.IsSessionActive(context.Background(), session.ID, user.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("check session: %v", err)
	}
	if active {
		t.Fatal("rename should revoke existing user sessions")
	}
}

func TestRenameUserValidation(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	seedPasswordTestUser(t, store, "admin", "old-password-123")
	seedPasswordTestUser(t, store, "reader", "old-password-123")
	if _, err := renameUser(context.Background(), sqlitePath, "missing", "Cheese"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing user error, got %v", err)
	}
	if _, err := renameUser(context.Background(), sqlitePath, "admin", "xy"); err == nil || !strings.Contains(err.Error(), "at least 3") {
		t.Fatalf("expected short username error, got %v", err)
	}
	if _, err := renameUser(context.Background(), sqlitePath, "admin", "reader"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate username error, got %v", err)
	}
}

func TestEnsureAdminUserCreatesAndRecoversAdministrator(t *testing.T) {
	store, sqlitePath := userPasswordTestStore(t)
	generated, err := ensureAdminUser(context.Background(), sqlitePath, "test-admin", cliPasswordOptions{Password: "Test-Only-Initial-Password!42"})
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	if generated != "" {
		t.Fatalf("unexpected generated password: %q", generated)
	}
	user, err := store.GetUserByUsername(context.Background(), "test-admin")
	if err != nil || user == nil || user.Role != "admin" {
		t.Fatalf("administrator not created correctly: user=%+v err=%v", user, err)
	}
	user.Role = "readonly"
	user.TwoFAEnabled = true
	user.TwoFASecret = "stale-secret"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureAdminUser(context.Background(), sqlitePath, "test-admin", cliPasswordOptions{Password: "Test-Only-Recovery-Password!84"}); err != nil {
		t.Fatalf("recover administrator: %v", err)
	}
	recovered, err := store.GetUserByUsername(context.Background(), "test-admin")
	if err != nil || recovered == nil || recovered.Role != "admin" || recovered.TwoFAEnabled || recovered.TwoFASecret != "" {
		t.Fatalf("administrator not recovered correctly: user=%+v err=%v", recovered, err)
	}
}

func userPasswordTestStore(t *testing.T) (*storage.SQLiteStore, string) {
	t.Helper()
	sqlitePath := t.TempDir() + "/cheesewaf.db"
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return store, sqlitePath
}

func seedPasswordTestUser(t *testing.T, store *storage.SQLiteStore, username, password string) *storage.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &storage.User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         "admin",
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}
