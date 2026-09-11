package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
)

func TestEnsureNoPendingMigrationFailsClosed(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "migration", "temporary-to-production.pending")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ensureNoPendingMigration(dataDir)
	if !errors.Is(err, climigration.ErrCutoverPending) {
		t.Fatalf("error=%v, want pending cutover", err)
	}
}

func TestEnsureNoPendingMigrationAllowsFreshDataDir(t *testing.T) {
	if err := ensureNoPendingMigration(filepath.Join(t.TempDir(), "fresh")); err != nil {
		t.Fatalf("fresh data dir rejected: %v", err)
	}
}

func TestEnsureNoPendingMigrationFailsClosedForInsecureExistingMigrationDir(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "migration"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureNoPendingMigration(dataDir); !errors.Is(err, climigration.ErrCutoverPending) {
		t.Fatalf("insecure existing migration directory accepted: %v", err)
	}
}
