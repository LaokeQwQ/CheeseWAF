package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrSQLiteSchemaTooNew means the database was written by a newer CheeseWAF
// version and must not be opened by this binary.
var ErrSQLiteSchemaTooNew = errors.New("newer SQLite schema version")

const sqliteSchemaVersion = 1

type sqliteMigration struct {
	version int
	name    string
	apply   func(context.Context, *sql.Tx) error
}

var sqliteMigrations = []sqliteMigration{
	{
		version: 1,
		name:    "initial schema",
		apply:   migrateSQLiteInitialSchema,
	},
}

type sqliteContextExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	// journal_mode cannot be changed inside a transaction. Keep connection
	// setup outside the versioned migration transaction.
	if _, err := s.db.ExecContext(ctx, `PRAGMA journal_mode = WAL`); err != nil {
		return fmt.Errorf("configure SQLite journal mode: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("configure SQLite foreign keys: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SQLite migration: %w", err)
	}
	rollback := func(cause error) error {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", cause, rollbackErr)
		}
		return cause
	}

	version, err := readSQLiteSchemaVersion(ctx, tx)
	if err != nil {
		return rollback(fmt.Errorf("read SQLite schema version: %w", err))
	}
	if version > sqliteSchemaVersion {
		return rollback(fmt.Errorf("%w: database=%d supported=%d", ErrSQLiteSchemaTooNew, version, sqliteSchemaVersion))
	}

	for _, migration := range sqliteMigrations {
		if migration.version <= version {
			continue
		}
		if err := migration.apply(ctx, tx); err != nil {
			return rollback(fmt.Errorf("apply SQLite migration %d (%s): %w", migration.version, migration.name, err))
		}
		if err := setSQLiteSchemaVersion(ctx, tx, migration.version); err != nil {
			return rollback(fmt.Errorf("record SQLite migration %d (%s): %w", migration.version, migration.name, err))
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SQLite migration: %w", err)
	}
	return nil
}

func readSQLiteSchemaVersion(ctx context.Context, db sqliteContextExecutor) (int, error) {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func setSQLiteSchemaVersion(ctx context.Context, db sqliteContextExecutor, version int) error {
	if version < 0 {
		return fmt.Errorf("invalid SQLite schema version %d", version)
	}
	_, err := db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, version))
	return err
}

func migrateSQLiteInitialSchema(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	if err := ensureColumns(ctx, tx, "sites", []sqliteColumnMigration{
		{column: "loadbalance", statement: `ALTER TABLE sites ADD COLUMN loadbalance TEXT NOT NULL DEFAULT 'round_robin'`},
		{column: "waf_enabled", statement: `ALTER TABLE sites ADD COLUMN waf_enabled INTEGER NOT NULL DEFAULT 1`},
		{column: "waf_mode", statement: `ALTER TABLE sites ADD COLUMN waf_mode TEXT NOT NULL DEFAULT 'block'`},
		{column: "paranoia_level", statement: `ALTER TABLE sites ADD COLUMN paranoia_level INTEGER NOT NULL DEFAULT 3`},
		{column: "advanced", statement: `ALTER TABLE sites ADD COLUMN advanced TEXT NOT NULL DEFAULT '{}'`},
	}); err != nil {
		return fmt.Errorf("upgrade sites columns: %w", err)
	}
	return ensureColumns(ctx, tx, "review_items", []sqliteColumnMigration{
		{column: "source", statement: `ALTER TABLE review_items ADD COLUMN source TEXT NOT NULL DEFAULT ''`},
		{column: "param_name", statement: `ALTER TABLE review_items ADD COLUMN param_name TEXT NOT NULL DEFAULT ''`},
		{column: "fingerprint", statement: `ALTER TABLE review_items ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`},
	})
}

type sqliteColumnMigration struct {
	column    string
	statement string
}

func ensureColumns(ctx context.Context, db sqliteContextExecutor, table string, migrations []sqliteColumnMigration) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	existing := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, migration := range migrations {
		if existing[migration.column] {
			continue
		}
		if _, err := db.ExecContext(ctx, migration.statement); err != nil {
			return err
		}
	}
	return nil
}

// schemaSQL is the immutable baseline for schema version 1. Future schema
// changes must be added as a new ordered migration above, not edited here.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domains TEXT NOT NULL,
  upstreams TEXT NOT NULL,
  listen_port INTEGER NOT NULL DEFAULT 80,
  loadbalance TEXT NOT NULL DEFAULT 'round_robin',
  enable_ssl INTEGER NOT NULL DEFAULT 0,
  cert_file TEXT NOT NULL DEFAULT '',
  key_file TEXT NOT NULL DEFAULT '',
  waf_enabled INTEGER NOT NULL DEFAULT 1,
  waf_mode TEXT NOT NULL DEFAULT 'block',
  paranoia_level INTEGER NOT NULL DEFAULT 3,
  advanced TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  pattern TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'uri',
  action TEXT NOT NULL DEFAULT 'block',
  severity TEXT NOT NULL DEFAULT 'medium',
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 100,
  FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  two_fa_enabled INTEGER NOT NULL DEFAULT 0,
  two_fa_secret TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  role TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'info',
  title TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  is_read INTEGER NOT NULL DEFAULT 0,
  is_pinned INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rules_site_id ON rules(site_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user_order ON notifications(user_id, is_pinned DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);

CREATE TABLE IF NOT EXISTS review_items (
  id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL DEFAULT '',
  site_id TEXT NOT NULL DEFAULT '',
  client_ip TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT '',
  uri TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL DEFAULT '',
  protection_level INTEGER NOT NULL DEFAULT 0,
  shape TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  param_name TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  ai_verdict TEXT NOT NULL DEFAULT '',
  decided_by_subject TEXT NOT NULL DEFAULT '',
  decided_by_name TEXT NOT NULL DEFAULT '',
  decided_by_role TEXT NOT NULL DEFAULT '',
  decided_at TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  applied_rule_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_items_site_status ON review_items(site_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_review_items_category_time ON review_items(category, created_at DESC);

CREATE TABLE IF NOT EXISTS site_promotes (
  site_id TEXT PRIMARY KEY,
  until_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_consumed (
  user_id TEXT NOT NULL,
  counter INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(user_id, counter)
);
CREATE INDEX IF NOT EXISTS idx_totp_consumed_expires ON totp_consumed(expires_at);
`
