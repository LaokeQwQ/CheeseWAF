package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
		Password:      "correct-horse-battery",
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
