package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

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
