package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestCompleteSetupRestoresFilesWhenCompletionMarkerFails(t *testing.T) {
	dataDir := t.TempDir()
	paths, cfg, store := setupFailureFixture(t, dataDir)
	originalConfig, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	originalConfigInfo, err := os.Stat(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	originalCert := []byte("existing certificate")
	if err := os.MkdirAll(filepath.Dir(paths.CertFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.CertFile, originalCert, 0o640); err != nil {
		t.Fatal(err)
	}

	_, err = CompleteSetup(context.Background(), CompleteOptions{
		Config:       cfg,
		ConfigPath:   paths.ConfigFile,
		Paths:        paths,
		Store:        store,
		markComplete: func(string) error { return errors.New("injected completion failure") },
	}, validSetupPayload())
	if err == nil {
		t.Fatal("expected setup failure")
	}
	assertSetupRolledBack(t, paths, cfg, store, originalConfig, originalConfigInfo.Mode().Perm())
	cert, err := os.ReadFile(paths.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert) != string(originalCert) {
		t.Fatalf("certificate changed after rollback: %q", cert)
	}
}

func TestCompleteSetupDoesNotImplicitlyRenameCaseVariantExistingUser(t *testing.T) {
	dataDir := t.TempDir()
	paths, cfg, store := setupFailureFixture(t, dataDir)
	if err := store.CreateUser(context.Background(), &storage.User{Username: "Admin", PasswordHash: "hash", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	_, err := CompleteSetup(context.Background(), CompleteOptions{
		Config:     cfg,
		ConfigPath: paths.ConfigFile,
		Paths:      paths,
		Store:      store,
	}, validSetupPayload())
	if !errors.Is(err, ErrSetupAlreadyComplete) {
		t.Fatalf("case variant must not be implicitly renamed, got %v", err)
	}
	user, err := store.GetUserByUsername(context.Background(), "Admin")
	if err != nil || user == nil || user.Username != "Admin" {
		t.Fatalf("existing user changed after rejected setup: user=%+v err=%v", user, err)
	}
}

func TestCompleteSetupRejectsExistingCanonicalUserWithoutMutatingAccountOrSessions(t *testing.T) {
	dataDir := t.TempDir()
	paths, cfg, store := setupFailureFixture(t, dataDir)
	ctx := context.Background()
	existing := &storage.User{
		Username:     "admin",
		PasswordHash: "old-password-hash",
		Role:         "readonly",
		TwoFAEnabled: true,
		TwoFASecret:  "existing-2fa-secret",
	}
	if err := store.CreateUser(ctx, existing); err != nil {
		t.Fatal(err)
	}
	before := *existing
	session := &storage.Session{
		ID:              "existing-session",
		UserID:          existing.ID,
		Username:        existing.Username,
		Role:            existing.Role,
		CredentialEpoch: existing.CredentialEpoch,
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
	}
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}

	_, err := CompleteSetup(ctx, CompleteOptions{
		Config:     cfg,
		ConfigPath: paths.ConfigFile,
		Paths:      paths,
		Store:      store,
	}, validSetupPayload())
	if !errors.Is(err, ErrSetupAlreadyComplete) {
		t.Fatalf("existing account must not be reinitialized, got %v", err)
	}
	if !strings.Contains(err.Error(), "waf-cli user ensure-admin admin --password-stdin") {
		t.Fatalf("recovery command missing from setup error: %v", err)
	}
	got, err := store.GetUserByUsername(ctx, before.Username)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != before.ID || got.Username != before.Username || got.PasswordHash != before.PasswordHash || got.Role != before.Role || got.TwoFAEnabled != before.TwoFAEnabled || got.TwoFASecret != before.TwoFASecret || !got.CreatedAt.Equal(before.CreatedAt) || !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("existing account was mutated by setup retry: before=%+v after=%+v", before, got)
	}
	active, err := store.IsSessionActive(ctx, session.ID, existing.ID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("setup retry must not revoke an existing session")
	}
	if !NeedsSetup(paths.DataDir) {
		t.Fatal("rejected setup retry unexpectedly wrote the completion marker")
	}
}

func TestCompleteSetupMultipleExistingUsersProvidesRecoveryCommand(t *testing.T) {
	dataDir := t.TempDir()
	paths, cfg, store := setupFailureFixture(t, dataDir)
	ctx := context.Background()
	for _, username := range []string{"admin", "reader"} {
		if err := store.CreateUser(ctx, &storage.User{Username: username, PasswordHash: "hash", Role: "readonly"}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := CompleteSetup(ctx, CompleteOptions{
		Config:     cfg,
		ConfigPath: paths.ConfigFile,
		Paths:      paths,
		Store:      store,
	}, validSetupPayload())
	if !errors.Is(err, ErrSetupAlreadyComplete) {
		t.Fatalf("multiple existing accounts must reject setup, got %v", err)
	}
	if !strings.Contains(err.Error(), "waf-cli user ensure-admin USERNAME --password-stdin") {
		t.Fatalf("multiple-account recovery command missing: %v", err)
	}
}

func TestCompleteSetupRemovesCompletionMarkerWhenUserPersistenceFails(t *testing.T) {
	dataDir := t.TempDir()
	paths, cfg, store := setupFailureFixture(t, dataDir)
	originalConfig, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	originalConfigInfo, err := os.Stat(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CompleteSetup(context.Background(), CompleteOptions{
		Config:     cfg,
		ConfigPath: paths.ConfigFile,
		Paths:      paths,
		Store:      store,
		persistUser: func(context.Context, storage.Store, *storage.User, bool) error {
			return errors.New("injected user persistence failure")
		},
	}, validSetupPayload())
	if err == nil {
		t.Fatal("expected setup failure")
	}
	assertSetupRolledBack(t, paths, cfg, store, originalConfig, originalConfigInfo.Mode().Perm())
}

func TestCompleteSetupCanRetryAfterUserPersistenceFailure(t *testing.T) {
	dataDir := t.TempDir()
	paths, cfg, store := setupFailureFixture(t, dataDir)
	ctx := context.Background()
	_, err := CompleteSetup(ctx, CompleteOptions{
		Config:     cfg,
		ConfigPath: paths.ConfigFile,
		Paths:      paths,
		Store:      store,
		persistUser: func(context.Context, storage.Store, *storage.User, bool) error {
			return errors.New("injected user persistence failure")
		},
	}, validSetupPayload())
	if err == nil {
		t.Fatal("expected first setup attempt to fail")
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 || !NeedsSetup(paths.DataDir) {
		t.Fatalf("failed setup left state that blocks a retry: users=%+v needsSetup=%v", users, NeedsSetup(paths.DataDir))
	}

	result, err := CompleteSetup(ctx, CompleteOptions{
		Config:     cfg,
		ConfigPath: paths.ConfigFile,
		Paths:      paths,
		Store:      store,
	}, validSetupPayload())
	if err != nil {
		t.Fatalf("valid retry failed: %v", err)
	}
	if result == nil || result.User == nil || result.User.Username != "admin" || NeedsSetup(paths.DataDir) {
		t.Fatalf("valid retry did not complete setup: result=%+v needsSetup=%v", result, NeedsSetup(paths.DataDir))
	}
}

func setupFailureFixture(t *testing.T, dataDir string) (DefaultPaths, *config.Config, storage.Store) {
	t.Helper()
	paths := ResolveDefaultPaths(DefaultOptions{DataDir: dataDir})
	if err := os.MkdirAll(filepath.Dir(paths.ConfigFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ConfigFile, DefaultConfigYAML(paths), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.AdminListen = "127.0.0.1:19443"
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenSQLite(paths.SQLiteFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return paths, cfg, store
}

func validSetupPayload() SetupPayload {
	return SetupPayload{
		Username:      "admin",
		Password:      "Correct-Horse-9x!",
		AdminListen:   "0.0.0.0:9443",
		AdminStrategy: "public_tls",
	}
}

func assertSetupRolledBack(t *testing.T, paths DefaultPaths, cfg *config.Config, store storage.Store, originalConfig []byte, originalMode os.FileMode) {
	t.Helper()
	if !NeedsSetup(paths.DataDir) {
		t.Fatal("completion marker survived failed setup")
	}
	afterConfig, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterConfig) != string(originalConfig) {
		t.Fatal("disk config was not restored")
	}
	afterInfo, err := os.Stat(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != originalMode {
		t.Fatalf("config mode was not restored: got %o want %o", afterInfo.Mode().Perm(), originalMode)
	}
	if cfg.Server.AdminListen != "127.0.0.1:19443" {
		t.Fatalf("memory config was not restored: %q", cfg.Server.AdminListen)
	}
	users, err := store.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Fatalf("administrator survived failed setup: %+v", users)
	}
}
