package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestOpenConfiguredManagementStoreUsesSQLiteForTemporaryProfile(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.SQLite.Path = filepath.Join(t.TempDir(), "temporary.db")

	store, err := openConfiguredManagementStore(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("open temporary management store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := os.Stat(cfg.Storage.SQLite.Path); err != nil {
		t.Fatalf("temporary SQLite database was not created: %v", err)
	}
}

func TestOpenConfiguredManagementStoreRefusesProductionSQLiteFallback(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://control.example.invalid/cheesewaf"
	cfg.Storage.SQLite.Path = filepath.Join(dir, "must-not-exist.db")

	store, err := openConfiguredManagementStore(context.Background(), &cfg)
	if store != nil {
		_ = store.Close()
		t.Fatal("production profile unexpectedly returned a management store")
	}
	if !errors.Is(err, config.ErrProductionStorageUnavailable) || !strings.Contains(err.Error(), "refusing SQLite fallback") {
		t.Fatalf("openConfiguredManagementStore() error = %v", err)
	}
	if _, statErr := os.Stat(cfg.Storage.SQLite.Path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("production profile touched SQLite path: %v", statErr)
	}
}

func TestOpenConfiguredManagementStoreRejectsNilProductionStore(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://control.example.invalid/cheesewaf"
	previous := openProductionManagementStore
	openProductionManagementStore = func(context.Context, config.ManagementPostgreSQLConfig) (storage.Store, error) {
		return nil, nil
	}
	t.Cleanup(func() { openProductionManagementStore = previous })
	if _, err := openConfiguredManagementStore(context.Background(), &cfg); !errors.Is(err, config.ErrProductionStorageUnavailable) {
		t.Fatalf("nil production store accepted: %v", err)
	}
}
