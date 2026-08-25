package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteMigrateRecordsCurrentSchemaVersion(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "schema-version.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("re-running migration: %v", err)
	}
}

func TestSQLiteMigrateUpgradesLegacySchemaAndPreservesData(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.db.Exec(`
CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domains TEXT NOT NULL,
  upstreams TEXT NOT NULL,
  listen_port INTEGER NOT NULL DEFAULT 80,
  enable_ssl INTEGER NOT NULL DEFAULT 0,
  cert_file TEXT NOT NULL DEFAULT '',
  key_file TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO sites(id, name, domains, upstreams, created_at, updated_at)
VALUES('legacy-site', 'legacy', '["legacy.test"]', '["127.0.0.1:9000"]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');`)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	site, err := store.GetSite(context.Background(), "legacy-site")
	if err != nil {
		t.Fatal(err)
	}
	if site == nil || site.Name != "legacy" || !strings.EqualFold(site.LoadBalance, "round_robin") {
		t.Fatalf("legacy site was not preserved and defaulted: %+v", site)
	}
	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}
}

func TestSQLiteMigrateRollsBackFailedMigration(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.Exec(`CREATE VIEW sites AS SELECT 'legacy' AS id`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background()); err == nil {
		t.Fatal("expected migration to fail for an incompatible sites view")
	}

	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("schema version after rollback = %d, want 0", version)
	}
	var tableName sql.NullString
	if err := store.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='rules'`).Scan(&tableName); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rules table survived failed migration: name=%q err=%v", tableName.String, err)
	}
}

func TestSQLiteMigrateRejectsNewerSchemaVersion(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "future.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background()); !errors.Is(err, ErrSQLiteSchemaTooNew) || !strings.Contains(err.Error(), "newer SQLite schema version") {
		t.Fatalf("Migrate error = %v, want newer SQLite schema version error", err)
	}
}
