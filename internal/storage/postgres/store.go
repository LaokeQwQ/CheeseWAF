// Package postgres implements the durable management storage.Store adapter.
// PostgreSQL is the management-plane source of truth; every security-sensitive
// mutation is committed in a database transaction.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	ErrInvalidStore = errors.New("invalid management PostgreSQL store")
	ErrSchemaTooNew = errors.New("newer management PostgreSQL schema version")
)

const schemaVersion = 2

const (
	defaultMaxOpenConns    = 8
	defaultMaxIdleConns    = 2
	defaultConnMaxIdleTime = 5 * time.Minute
	defaultConnMaxLifetime = 30 * time.Minute
)

// Store is safe for concurrent callers. database/sql and PostgreSQL provide
// connection pooling; transaction boundaries in this adapter provide the
// atomic identity, epoch, and session semantics.
type Store struct {
	db       *sql.DB
	roleKeys map[string]struct{}
}

var _ storage.Store = (*Store)(nil)

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalidStore
	}
	configurePool(db)
	return &Store{db: db, roleKeys: cloneRoleKeys(defaultRoleKeys)}, nil
}

// NewWithRoles accepts the exact keys from the active apisec.permissions map.
// Values in that map are permission expressions and are not role identities.
func NewWithRoles(db *sql.DB, permissions map[string][]string) (*Store, error) {
	if db == nil {
		return nil, ErrInvalidStore
	}
	keys := make(map[string]struct{}, len(permissions))
	for role := range permissions {
		if validateRoleSyntax(role) == nil {
			keys[role] = struct{}{}
		}
	}
	if len(keys) == 0 {
		keys = cloneRoleKeys(defaultRoleKeys)
	}
	return &Store{db: db, roleKeys: keys}, nil
}

var defaultRoleKeys = map[string]struct{}{"admin": {}, "readonly": {}}

func cloneRoleKeys(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func configurePool(db *sql.DB) {
	if db == nil {
		return
	}
	// Preserve an embedding application's explicit cap (the integration tests
	// use one connection to isolate a temporary search_path), while ensuring a
	// fresh production handle is bounded and periodically refreshes connections.
	if db.Stats().MaxOpenConnections == 0 {
		db.SetMaxOpenConns(defaultMaxOpenConns)
	}
	db.SetMaxIdleConns(defaultMaxIdleConns)
	db.SetConnMaxIdleTime(defaultConnMaxIdleTime)
	db.SetConnMaxLifetime(defaultConnMaxLifetime)
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("%w: DSN is required", ErrInvalidStore)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrInvalidStore, err)
	}
	s, err := New(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ping: %v", ErrInvalidStore, err)
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Health verifies the management database is reachable and its migration
// ledger is at the version supported by this binary.
func (s *Store) Health(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `SELECT version FROM cheesewaf_storage_schema WHERE id=1`).Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("%w: database=%d supported=%d", ErrSchemaTooNew, version, schemaVersion)
	}
	if version < schemaVersion {
		return fmt.Errorf("management PostgreSQL schema is not migrated: database=%d supported=%d", version, schemaVersion)
	}
	return nil
}

func (s *Store) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin migration: %v", ErrInvalidStore, err)
	}
	defer tx.Rollback()
	// A transaction advisory lock makes concurrent processes serialize schema
	// creation without relying on process-local locks.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(847392104)`); err != nil {
		return err
	}
	for _, statement := range migrationStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%w: migration: %v", ErrInvalidStore, err)
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT version FROM cheesewaf_storage_schema WHERE id=1 FOR UPDATE`).Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("%w: database=%d supported=%d", ErrSchemaTooNew, version, schemaVersion)
	}
	if version < schemaVersion {
		if _, err := tx.ExecContext(ctx, `UPDATE cheesewaf_storage_schema SET version=$1, updated_at=now() WHERE id=1`, schemaVersion); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var migrationStatements = []string{
	`CREATE TABLE IF NOT EXISTS cheesewaf_storage_schema (id SMALLINT PRIMARY KEY CHECK (id=1), version INTEGER NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
	`INSERT INTO cheesewaf_storage_schema(id,version) VALUES (1,0) ON CONFLICT (id) DO NOTHING`,
	`CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, domains JSONB NOT NULL DEFAULT '[]'::jsonb, upstreams JSONB NOT NULL DEFAULT '[]'::jsonb, listen_port INTEGER NOT NULL DEFAULT 80, loadbalance TEXT NOT NULL DEFAULT 'round_robin', enable_ssl BOOLEAN NOT NULL DEFAULT FALSE, cert_file TEXT NOT NULL DEFAULT '', key_file TEXT NOT NULL DEFAULT '', waf_enabled BOOLEAN NOT NULL DEFAULT TRUE, waf_mode TEXT NOT NULL DEFAULT 'block', paranoia_level INTEGER NOT NULL DEFAULT 3, advanced JSONB NOT NULL DEFAULT '{}'::jsonb, enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS rules (id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', pattern TEXT NOT NULL, location TEXT NOT NULL DEFAULT 'uri', action TEXT NOT NULL DEFAULT 'block', severity TEXT NOT NULL DEFAULT 'medium', enabled BOOLEAN NOT NULL DEFAULT TRUE, priority INTEGER NOT NULL DEFAULT 100)`,
	`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', two_fa_enabled BOOLEAN NOT NULL DEFAULT FALSE, two_fa_secret TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, credential_epoch BIGINT NOT NULL DEFAULT 0 CHECK (credential_epoch >= 0))`,
	`CREATE TABLE IF NOT EXISTS admin_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, username TEXT NOT NULL, role TEXT NOT NULL, issued_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, credential_epoch BIGINT NOT NULL DEFAULT 0 CHECK (credential_epoch >= 0))`,
	`CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '', is_read BOOLEAN NOT NULL DEFAULT FALSE, is_pinned BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS review_items (id TEXT PRIMARY KEY, trace_id TEXT NOT NULL DEFAULT '', site_id TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '', uri TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL DEFAULT '', protection_level INTEGER NOT NULL DEFAULT 0, shape TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', param_name TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', ai_verdict TEXT NOT NULL DEFAULT '', decided_by_subject TEXT NOT NULL DEFAULT '', decided_by_name TEXT NOT NULL DEFAULT '', decided_by_role TEXT NOT NULL DEFAULT '', decided_at TIMESTAMPTZ NULL, decision TEXT NOT NULL DEFAULT '', applied_rule_id TEXT NOT NULL DEFAULT '', decision_claim TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS site_promotes (site_id TEXT PRIMARY KEY, until_at TIMESTAMPTZ NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS totp_consumed (user_id TEXT NOT NULL, counter BIGINT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY(user_id,counter))`,
	`CREATE TABLE IF NOT EXISTS user_username_repairs (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, old_username TEXT NOT NULL, new_username TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL, revoked_sessions BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS cheesewaf_migration_cutovers (snapshot_id TEXT PRIMARY KEY, config_digest TEXT NOT NULL, candidate_digest TEXT NOT NULL, initial_state_hash TEXT NOT NULL, token_metadata_digest TEXT NOT NULL, actor_id TEXT NOT NULL, confirmation_id TEXT NOT NULL UNIQUE, cluster_id TEXT NOT NULL, committed_at TIMESTAMPTZ NOT NULL)`,
	`ALTER TABLE cheesewaf_migration_cutovers ADD COLUMN IF NOT EXISTS token_metadata_digest TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'`,
	`CREATE TABLE IF NOT EXISTS cheesewaf_migration_legacy_tokens (snapshot_id TEXT NOT NULL REFERENCES cheesewaf_migration_cutovers(snapshot_id) ON DELETE RESTRICT, token_id TEXT NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL, scopes JSONB NOT NULL DEFAULT '[]'::jsonb, notes TEXT NOT NULL DEFAULT '', was_enabled BOOLEAN NOT NULL, never_expire BOOLEAN NOT NULL, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, source_revoked_at TIMESTAMPTZ, migrated_at TIMESTAMPTZ NOT NULL, actor_id TEXT NOT NULL, status TEXT NOT NULL CHECK (status='revoked'), PRIMARY KEY(snapshot_id,token_id))`,
	`CREATE INDEX IF NOT EXISTS idx_migration_legacy_tokens_snapshot ON cheesewaf_migration_legacy_tokens(snapshot_id,token_id)`,
	`ALTER TABLE sites ADD COLUMN IF NOT EXISTS loadbalance TEXT NOT NULL DEFAULT 'round_robin'`,
	`ALTER TABLE sites ADD COLUMN IF NOT EXISTS waf_enabled BOOLEAN NOT NULL DEFAULT TRUE`,
	`ALTER TABLE sites ADD COLUMN IF NOT EXISTS waf_mode TEXT NOT NULL DEFAULT 'block'`,
	`ALTER TABLE sites ADD COLUMN IF NOT EXISTS paranoia_level INTEGER NOT NULL DEFAULT 3`,
	`ALTER TABLE sites ADD COLUMN IF NOT EXISTS advanced JSONB NOT NULL DEFAULT '{}'::jsonb`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS credential_epoch BIGINT NOT NULL DEFAULT 0`,
	`ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS credential_epoch BIGINT NOT NULL DEFAULT 0`,
	`ALTER TABLE review_items ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE review_items ADD COLUMN IF NOT EXISTS param_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE review_items ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE review_items ADD COLUMN IF NOT EXISTS decision_claim TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS idx_rules_site_id ON rules(site_id)`,
	`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
	`CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_notifications_user_order ON notifications(user_id,is_pinned,created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id,is_read)`,
	`CREATE INDEX IF NOT EXISTS idx_review_items_site_status ON review_items(site_id,status,created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_review_items_category_time ON review_items(category,created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_totp_consumed_expires ON totp_consumed(expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_user_username_repairs_user_time ON user_username_repairs(user_id,created_at DESC)`,
	`CREATE OR REPLACE FUNCTION cheesewaf_reject_repair_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'user username repair audit is append-only'; END; $$`,
	`DROP TRIGGER IF EXISTS prevent_user_username_repair_update ON user_username_repairs`,
	`CREATE TRIGGER prevent_user_username_repair_update BEFORE UPDATE ON user_username_repairs FOR EACH ROW EXECUTE FUNCTION cheesewaf_reject_repair_mutation()`,
	`DROP TRIGGER IF EXISTS prevent_user_username_repair_delete ON user_username_repairs`,
	`CREATE TRIGGER prevent_user_username_repair_delete BEFORE DELETE ON user_username_repairs FOR EACH ROW EXECUTE FUNCTION cheesewaf_reject_repair_mutation()`,
}

// rebind converts database/sql's portable question mark placeholders into PGX
// numbered parameters. Question marks inside SQL string literals are left alone.
func rebind(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	single := false
	dollar := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '\'' && !dollar {
			if single && i+1 < len(query) && query[i+1] == '\'' {
				b.WriteByte(c)
				b.WriteByte(c)
				i++
				continue
			}
			single = !single
			b.WriteByte(c)
			continue
		}
		if c == '$' && !single {
			dollar = !dollar
			b.WriteByte(c)
			continue
		}
		if c == '?' && !single && !dollar {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, rebind(query), args...)
}
func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, rebind(query), args...)
}
func (s *Store) row(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, rebind(query), args...)
}

type scanner interface{ Scan(...any) error }
type dbTime struct{ time.Time }
type dbBool bool

func (b *dbBool) Scan(value any) error {
	switch v := value.(type) {
	case bool:
		*b = dbBool(v)
	case int64:
		*b = dbBool(v != 0)
	case int:
		*b = dbBool(v != 0)
	case string:
		*b = dbBool(strings.EqualFold(v, "true") || strings.EqualFold(v, "t") || v == "1")
	case []byte:
		return b.Scan(string(v))
	case nil:
		*b = false
	default:
		return fmt.Errorf("unsupported boolean type %T", value)
	}
	return nil
}

func (t *dbTime) Scan(value any) error {
	if value == nil {
		t.Time = time.Time{}
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		t.Time = v.UTC()
		return nil
	case string:
		parsed, err := parseTime(v)
		if err != nil {
			return err
		}
		t.Time = parsed
		return nil
	case []byte:
		parsed, err := parseTime(string(v))
		if err != nil {
			return err
		}
		t.Time = parsed
		return nil
	default:
		return fmt.Errorf("unsupported timestamp type %T", value)
	}
}
func parseTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}
func timestamp(t time.Time) any {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}
func optionalTimestamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
func encodeJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{}`)
	}
	return b
}
func encodeStrings(v []string) []byte {
	if v == nil {
		v = []string{}
	}
	return encodeJSON(v)
}
func decodeStrings(raw []byte) []string { var v []string; _ = json.Unmarshal(raw, &v); return v }
func decodeAdvanced(raw []byte) storage.SiteAdvanced {
	var v storage.SiteAdvanced
	_ = json.Unmarshal(raw, &v)
	return v
}
func boolValue(v bool) bool { return v }

func ensureSite(site *storage.Site) {
	now := time.Now().UTC()
	if site.ID == "" {
		site.ID = uuid.NewString()
	}
	if site.CreatedAt.IsZero() {
		site.CreatedAt = now
	}
	if site.UpdatedAt.IsZero() {
		site.UpdatedAt = now
	}
	if site.ListenPort == 0 {
		site.ListenPort = 80
	}
	ensureSiteDefaults(site)
}
func ensureSiteDefaults(site *storage.Site) {
	if site.LoadBalance == "" {
		site.LoadBalance = "round_robin"
	}
	if site.WAFMode == "" {
		site.WAFMode = "block"
		site.WAFEnabled = true
	}
	if site.Advanced.Certificate.Mode == "" {
		site.Advanced.Certificate.Mode = "file"
	}
	if site.Advanced.Certificate.MinTLSVersion == "" {
		site.Advanced.Certificate.MinTLSVersion = "1.2"
	}
	if site.Advanced.Certificate.ACME.Env == nil {
		site.Advanced.Certificate.ACME.Env = map[string]string{}
	}
	if site.Advanced.Certificate.ACME.KeyType == "" {
		site.Advanced.Certificate.ACME.KeyType = "ec-256"
	}
	if site.Advanced.Certificate.ACME.Server == "" {
		site.Advanced.Certificate.ACME.Server = "letsencrypt"
	}
	if site.Advanced.Certificate.ACME.ACMESHPath == "" {
		site.Advanced.Certificate.ACME.ACMESHPath = "acme.sh"
	}
	if len(site.Advanced.Certificate.ACME.Domains) == 0 {
		site.Advanced.Certificate.ACME.Domains = append([]string(nil), site.Domains...)
	}
	if site.Advanced.Origin.Scheme == "" {
		site.Advanced.Origin.Scheme = "http"
	}
	if site.Advanced.Origin.ProxyTimeout == "" {
		site.Advanced.Origin.ProxyTimeout = "30s"
	}
	if site.Advanced.Origin.MaxBodyBytes == 0 {
		site.Advanced.Origin.MaxBodyBytes = 64 * 1024 * 1024
	}
	if site.Advanced.Origin.MaxHeaderSize == 0 {
		site.Advanced.Origin.MaxHeaderSize = 1 << 20
	}
	if site.Advanced.HealthCheck.Path == "" {
		site.Advanced.HealthCheck.Path = "/"
	}
	if site.Advanced.HealthCheck.Interval == "" {
		site.Advanced.HealthCheck.Interval = "30s"
	}
	if site.Advanced.HealthCheck.Timeout == "" {
		site.Advanced.HealthCheck.Timeout = "3s"
	}
	if site.Advanced.HealthCheck.HealthyThreshold == 0 {
		site.Advanced.HealthCheck.HealthyThreshold = 1
	}
	if site.Advanced.HealthCheck.UnhealthyThreshold == 0 {
		site.Advanced.HealthCheck.UnhealthyThreshold = 3
	}
	if site.Advanced.Response.MaxBodyBytes == 0 {
		site.Advanced.Response.MaxBodyBytes = 2 * 1024 * 1024
	}
}
func ensureUser(user *storage.User) {
	now := time.Now().UTC()
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.Role == "" {
		user.Role = "admin"
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}
}
func ensureSession(v *storage.Session) {
	now := time.Now().UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = now
	}
	if v.IssuedAt.IsZero() {
		v.IssuedAt = now
	}
}

func validateRepairIdentity(field, value string) error {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
		return fmt.Errorf("%s must be non-empty and contain only visible ASCII characters without whitespace", field)
	}
	return nil
}

func validateRoleSyntax(role string) error {
	if role == "" || strings.ContainsAny(role, "*:") || strings.IndexFunc(role, func(r rune) bool {
		return r < '!' || r > '~' || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0 {
		return errors.New("role must be a configured role name, not a permission expression")
	}
	return nil
}

func validateRole(role string) error { return validateRoleSyntax(role) }

func roleAllowed(keys map[string]struct{}, role string) bool {
	if validateRoleSyntax(role) != nil {
		return false
	}
	_, ok := keys[role]
	return ok
}

func (s *Store) validatePersistedRole(role string) error {
	if !roleAllowed(s.roleKeys, role) {
		return fmt.Errorf("%w: role %q is not configured", ErrInvalidStore, role)
	}
	return nil
}
func validateRepairReason(reason string) error {
	if !utf8.ValidString(reason) || strings.TrimSpace(reason) == "" {
		return errors.New("repair reason is required and must be valid UTF-8")
	}
	if len([]rune(reason)) > 512 {
		return errors.New("repair reason must contain at most 512 characters")
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("repair reason must not contain control or formatting characters")
		}
	}
	return nil
}

const siteColumns = `id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,paranoia_level,advanced,enabled,created_at,updated_at`

func scanSite(row scanner) (*storage.Site, error) {
	var v storage.Site
	var enableSSL, wafEnabled, enabled dbBool
	var domains, upstreams, advanced []byte
	var created, updated dbTime
	if err := row.Scan(&v.ID, &v.Name, &domains, &upstreams, &v.ListenPort, &v.LoadBalance, &enableSSL, &v.CertFile, &v.KeyFile, &wafEnabled, &v.WAFMode, &v.ParanoiaLevel, &advanced, &enabled, &created, &updated); err != nil {
		return nil, err
	}
	v.EnableSSL, v.WAFEnabled, v.Enabled = bool(enableSSL), bool(wafEnabled), bool(enabled)
	v.Domains = decodeStrings(domains)
	v.Upstreams = decodeStrings(upstreams)
	v.Advanced = decodeAdvanced(advanced)
	v.CreatedAt = created.Time
	v.UpdatedAt = updated.Time
	ensureSiteDefaults(&v)
	return &v, nil
}
func (s *Store) ListSites(ctx context.Context) ([]storage.Site, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	rows, err := s.query(ctx, `SELECT `+siteColumns+` FROM sites ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storage.Site{}
	for rows.Next() {
		v, e := scanSite(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}
func (s *Store) GetSite(ctx context.Context, id string) (*storage.Site, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	v, e := scanSite(s.row(ctx, `SELECT `+siteColumns+` FROM sites WHERE id=?`, id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return v, e
}
func (s *Store) CreateSite(ctx context.Context, v *storage.Site) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("site is nil")
	}
	ensureSite(v)
	_, e := s.exec(ctx, `INSERT INTO sites(`+siteColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, v.ID, v.Name, encodeStrings(v.Domains), encodeStrings(v.Upstreams), v.ListenPort, v.LoadBalance, v.EnableSSL, v.CertFile, v.KeyFile, v.WAFEnabled, v.WAFMode, v.ParanoiaLevel, encodeJSON(v.Advanced), v.Enabled, timestamp(v.CreatedAt), timestamp(v.UpdatedAt))
	return e
}
func (s *Store) UpdateSite(ctx context.Context, v *storage.Site) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("site is nil")
	}
	v.UpdatedAt = time.Now().UTC()
	_, e := s.exec(ctx, `UPDATE sites SET name=?,domains=?,upstreams=?,listen_port=?,loadbalance=?,enable_ssl=?,cert_file=?,key_file=?,waf_enabled=?,waf_mode=?,paranoia_level=?,advanced=?,enabled=?,updated_at=? WHERE id=?`, v.Name, encodeStrings(v.Domains), encodeStrings(v.Upstreams), v.ListenPort, v.LoadBalance, v.EnableSSL, v.CertFile, v.KeyFile, v.WAFEnabled, v.WAFMode, v.ParanoiaLevel, encodeJSON(v.Advanced), v.Enabled, v.UpdatedAt, v.ID)
	return e
}

// RestoreSite writes a previously read site snapshot without changing its timestamps.
func (s *Store) RestoreSite(ctx context.Context, v *storage.Site) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("site is nil")
	}
	_, e := s.exec(ctx, `UPDATE sites SET name=?,domains=?,upstreams=?,listen_port=?,loadbalance=?,enable_ssl=?,cert_file=?,key_file=?,waf_enabled=?,waf_mode=?,paranoia_level=?,advanced=?,enabled=?,created_at=?,updated_at=? WHERE id=?`, v.Name, encodeStrings(v.Domains), encodeStrings(v.Upstreams), v.ListenPort, v.LoadBalance, v.EnableSSL, v.CertFile, v.KeyFile, v.WAFEnabled, v.WAFMode, v.ParanoiaLevel, encodeJSON(v.Advanced), v.Enabled, v.CreatedAt, v.UpdatedAt, v.ID)
	return e
}

func NormalizeSiteForWrite(v *storage.Site) {
	if v != nil {
		ensureSite(v)
	}
}
func (s *Store) DeleteSite(ctx context.Context, id string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM review_items WHERE site_id=?`, `DELETE FROM site_promotes WHERE site_id=?`, `DELETE FROM sites WHERE id=?`} {
		if _, e = tx.ExecContext(ctx, rebind(q), id); e != nil {
			return e
		}
	}
	return tx.Commit()
}

const ruleColumns = `id,site_id,name,description,pattern,location,action,severity,enabled,priority`

func scanRule(row scanner) (*storage.Rule, error) {
	var v storage.Rule
	var enabled dbBool
	if err := row.Scan(&v.ID, &v.SiteID, &v.Name, &v.Description, &v.Pattern, &v.Location, &v.Action, &v.Severity, &enabled, &v.Priority); err != nil {
		return nil, err
	}
	v.Enabled = bool(enabled)
	return &v, nil
}
func (s *Store) ListRules(ctx context.Context, siteID string) ([]storage.Rule, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	rows, e := s.query(ctx, `SELECT `+ruleColumns+` FROM rules WHERE (?='' OR site_id=?) ORDER BY priority,id`, siteID, siteID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []storage.Rule{}
	for rows.Next() {
		v, e := scanRule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}
func (s *Store) GetRule(ctx context.Context, id string) (*storage.Rule, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	v, e := scanRule(s.row(ctx, `SELECT `+ruleColumns+` FROM rules WHERE id=?`, id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return v, e
}
func (s *Store) CreateRule(ctx context.Context, v *storage.Rule) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("rule is nil")
	}
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	if v.Action == "" {
		v.Action = "block"
	}
	if v.Location == "" {
		v.Location = "uri"
	}
	if v.Severity == "" {
		v.Severity = "medium"
	}
	_, e := s.exec(ctx, `INSERT INTO rules(`+ruleColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?)`, v.ID, v.SiteID, v.Name, v.Description, v.Pattern, v.Location, v.Action, v.Severity, v.Enabled, v.Priority)
	return e
}
func (s *Store) UpdateRule(ctx context.Context, v *storage.Rule) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("rule is nil")
	}
	_, e := s.exec(ctx, `UPDATE rules SET site_id=?,name=?,description=?,pattern=?,location=?,action=?,severity=?,enabled=?,priority=? WHERE id=?`, v.SiteID, v.Name, v.Description, v.Pattern, v.Location, v.Action, v.Severity, v.Enabled, v.Priority, v.ID)
	return e
}
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	_, e := s.exec(ctx, `DELETE FROM rules WHERE id=?`, id)
	return e
}

const userColumns = `id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch`

func scanUser(row scanner) (*storage.User, error) {
	var v storage.User
	var twoFA dbBool
	var created, updated dbTime
	if err := row.Scan(&v.ID, &v.Username, &v.PasswordHash, &v.Role, &twoFA, &v.TwoFASecret, &created, &updated, &v.CredentialEpoch); err != nil {
		return nil, err
	}
	v.TwoFAEnabled = bool(twoFA)
	v.CreatedAt = created.Time
	v.UpdatedAt = updated.Time
	if err := validateRoleSyntax(v.Role); err != nil {
		return nil, err
	}
	return &v, nil
}
func (s *Store) GetUserByUsername(ctx context.Context, name string) (*storage.User, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	v, e := scanUser(s.row(ctx, `SELECT `+userColumns+` FROM users WHERE username=?`, name))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e == nil {
		e = s.validatePersistedRole(v.Role)
	}
	return v, e
}
func (s *Store) GetUserByID(ctx context.Context, id string) (*storage.User, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	v, e := scanUser(s.row(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e == nil {
		e = s.validatePersistedRole(v.Role)
	}
	return v, e
}
func (s *Store) ListUsers(ctx context.Context) ([]storage.User, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	rows, e := s.query(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []storage.User{}
	for rows.Next() {
		v, e := scanUser(rows)
		if e != nil {
			return nil, e
		}
		if e := s.validatePersistedRole(v.Role); e != nil {
			return nil, e
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}
func (s *Store) CreateUser(ctx context.Context, v *storage.User) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("user is nil")
	}
	if err := identity.ValidateUsername(v.Username); err != nil {
		return err
	}
	if err := s.validatePersistedRole(v.Role); err != nil {
		return err
	}
	if v.ID != "" {
		if err := validateRepairIdentity("user ID", v.ID); err != nil {
			return err
		}
	}
	ensureUser(v)
	_, e := s.exec(ctx, `INSERT INTO users(`+userColumns+`) VALUES(?,?,?,?,?,?,?,?,?)`, v.ID, v.Username, v.PasswordHash, v.Role, v.TwoFAEnabled, v.TwoFASecret, timestamp(v.CreatedAt), timestamp(v.UpdatedAt), v.CredentialEpoch)
	return e
}

func (s *Store) UpdateUser(ctx context.Context, v *storage.User) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("user is nil")
	}
	if err := validateRepairIdentity("user ID", v.ID); err != nil {
		return err
	}
	if err := identity.ValidateUsername(v.Username); err != nil {
		return err
	}
	if err := s.validatePersistedRole(v.Role); err != nil {
		return err
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var old storage.User
	var oldTwoFA dbBool
	var c, u dbTime
	e = tx.QueryRowContext(ctx, rebind(`SELECT `+userColumns+` FROM users WHERE id=? FOR UPDATE`), v.ID).Scan(&old.ID, &old.Username, &old.PasswordHash, &old.Role, &oldTwoFA, &old.TwoFASecret, &c, &u, &old.CredentialEpoch)
	if errors.Is(e, sql.ErrNoRows) {
		return storage.ErrUserNotFound
	}
	if e != nil {
		return e
	}
	old.CreatedAt = c.Time
	old.UpdatedAt = u.Time
	old.TwoFAEnabled = bool(oldTwoFA)
	if err := s.validatePersistedRole(old.Role); err != nil {
		return err
	}
	if v.CredentialEpoch != old.CredentialEpoch {
		return storage.ErrCredentialEpochChanged
	}
	if err := identity.ValidateUsername(old.Username); err != nil {
		return err
	}
	changed := old.Username != v.Username || old.PasswordHash != v.PasswordHash || old.Role != v.Role || old.TwoFAEnabled != v.TwoFAEnabled || old.TwoFASecret != v.TwoFASecret
	next := old.CredentialEpoch
	if changed {
		if next >= uint64(1<<63-1) {
			return fmt.Errorf("%w: epoch exhausted", storage.ErrCredentialEpochChanged)
		}
		next++
	}
	now := time.Now().UTC()
	res, e := tx.ExecContext(ctx, rebind(`UPDATE users SET username=?,password_hash=?,role=?,two_fa_enabled=?,two_fa_secret=?,updated_at=?,credential_epoch=? WHERE id=? AND credential_epoch=?`), v.Username, v.PasswordHash, v.Role, v.TwoFAEnabled, v.TwoFASecret, now, next, v.ID, old.CredentialEpoch)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return storage.ErrCredentialEpochChanged
	}
	if changed {
		if _, e = tx.ExecContext(ctx, rebind(`UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at IS NULL`), now, now, v.ID); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	v.UpdatedAt = now
	v.CredentialEpoch = next
	return nil
}
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	_, e := s.exec(ctx, `DELETE FROM users WHERE id=?`, id)
	return e
}

// lockUser serializes all credential and session mutations for one immutable
// user ID. Locking the parent row closes the create-session/revoke race.
func lockUser(ctx context.Context, tx *sql.Tx, id string) (*storage.User, error) {
	v, e := scanUser(tx.QueryRowContext(ctx, rebind(`SELECT `+userColumns+` FROM users WHERE id=? FOR UPDATE`), id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, storage.ErrUserNotFound
	}
	return v, e
}
func validateSession(v *storage.Session) error {
	if v == nil {
		return errors.New("session is nil")
	}
	if e := validateRepairIdentity("session ID", v.ID); e != nil {
		return e
	}
	if e := validateRepairIdentity("user ID", v.UserID); e != nil {
		return e
	}
	if e := identity.ValidateUsername(v.Username); e != nil {
		return e
	}
	if e := validateRole(v.Role); e != nil {
		return e
	}
	if v.ExpiresAt.IsZero() {
		return errors.New("session expiry is required")
	}
	return nil
}
func insertSession(ctx context.Context, tx *sql.Tx, v *storage.Session) error {
	_, e := tx.ExecContext(ctx, rebind(`INSERT INTO admin_sessions(id,user_id,username,role,issued_at,expires_at,revoked_at,created_at,updated_at,credential_epoch) VALUES(?,?,?,?,?,?,?,?,?,?)`), v.ID, v.UserID, v.Username, v.Role, v.IssuedAt, v.ExpiresAt, optionalTimestamp(v.RevokedAt), v.CreatedAt, v.UpdatedAt, v.CredentialEpoch)
	return e
}
func sameCredentials(user *storage.User, session *storage.Session) bool {
	return user.CredentialEpoch == session.CredentialEpoch && user.Username == session.Username && user.Role == session.Role
}
func (s *Store) CreateSession(ctx context.Context, v *storage.Session) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if e := validateSession(v); e != nil {
		return e
	}
	ensureSession(v)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	user, e := lockUser(ctx, tx, v.UserID)
	if e != nil {
		return e
	}
	if e := s.validatePersistedRole(user.Role); e != nil {
		return e
	}
	if !sameCredentials(user, v) {
		return storage.ErrCredentialEpochChanged
	}
	if e := identity.ValidateUsername(user.Username); e != nil {
		return e
	}
	if e = insertSession(ctx, tx, v); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) RotateSession(ctx context.Context, oldID, userID string, next *storage.Session) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if e := validateRepairIdentity("session ID", oldID); e != nil {
		return e
	}
	if e := validateRepairIdentity("user ID", userID); e != nil {
		return e
	}
	if e := validateSession(next); e != nil {
		return e
	}
	if next.UserID != userID {
		return storage.ErrCredentialEpochChanged
	}
	if next.ID == oldID {
		return errors.New("next session ID must be different")
	}
	ensureSession(next)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	user, e := lockUser(ctx, tx, userID)
	if e != nil {
		return e
	}
	if e := s.validatePersistedRole(user.Role); e != nil {
		return e
	}
	if !sameCredentials(user, next) {
		return storage.ErrCredentialEpochChanged
	}
	now := time.Now().UTC()
	res, e := tx.ExecContext(ctx, rebind(`UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL AND credential_epoch=?`), now, now, oldID, userID, user.CredentialEpoch)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return storage.ErrSessionNotFound
	}
	if e = insertSession(ctx, tx, next); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) RevokeSession(ctx context.Context, id, userID string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if e := validateRepairIdentity("session ID", id); e != nil {
		return e
	}
	if e := validateRepairIdentity("user ID", userID); e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	user, e := lockUser(ctx, tx, userID)
	if e != nil {
		return e
	}
	if e := s.validatePersistedRole(user.Role); e != nil {
		return e
	}
	now := time.Now().UTC()
	res, e := tx.ExecContext(ctx, rebind(`UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL`), now, now, id, userID)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return storage.ErrSessionNotFound
	}
	return tx.Commit()
}
func (s *Store) RevokeUserSessions(ctx context.Context, userID, exceptID string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if e := validateRepairIdentity("user ID", userID); e != nil {
		return e
	}
	if exceptID != "" {
		if e := validateRepairIdentity("except session ID", exceptID); e != nil {
			return e
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	user, e := lockUser(ctx, tx, userID)
	if e != nil {
		return e
	}
	if e := s.validatePersistedRole(user.Role); e != nil {
		return e
	}
	if user.CredentialEpoch >= uint64(1<<63-1) {
		return fmt.Errorf("%w: epoch exhausted", storage.ErrCredentialEpochChanged)
	}
	next := user.CredentialEpoch + 1
	now := time.Now().UTC()
	res, e := tx.ExecContext(ctx, rebind(`UPDATE users SET credential_epoch=?,updated_at=? WHERE id=? AND credential_epoch=?`), next, now, userID, user.CredentialEpoch)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return storage.ErrCredentialEpochChanged
	}
	q := `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at IS NULL`
	args := []any{now, now, userID}
	if exceptID != "" {
		q += ` AND id<>?`
		args = append(args, exceptID)
	}
	if _, e = tx.ExecContext(ctx, rebind(q), args...); e != nil {
		return e
	}
	if exceptID != "" {
		if _, e = tx.ExecContext(ctx, rebind(`UPDATE admin_sessions SET credential_epoch=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL AND credential_epoch=?`), next, now, exceptID, userID, user.CredentialEpoch); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) IsSessionActive(ctx context.Context, id, userID string, now time.Time) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, ErrInvalidStore
	}
	if id == "" || userID == "" {
		return false, nil
	}
	if e := validateRepairIdentity("session ID", id); e != nil {
		return false, e
	}
	if e := validateRepairIdentity("user ID", userID); e != nil {
		return false, e
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var active bool
	e := s.row(ctx, `SELECT EXISTS(SELECT 1 FROM admin_sessions AS s JOIN users AS u ON u.id=s.user_id AND u.username=s.username AND u.role=s.role AND u.credential_epoch=s.credential_epoch WHERE s.id=? AND s.user_id=? AND s.revoked_at IS NULL AND s.expires_at>?)`, id, userID, now).Scan(&active)
	return active, e
}
func (s *Store) PruneSessions(ctx context.Context, before time.Time) (int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, ErrInvalidStore
	}
	if before.IsZero() {
		before = time.Now().UTC()
	}
	res, e := s.exec(ctx, `DELETE FROM admin_sessions WHERE expires_at<? OR (revoked_at IS NOT NULL AND revoked_at<?)`, before, before)
	if e != nil {
		return 0, e
	}
	return res.RowsAffected()
}

func (s *Store) RepairUserUsername(ctx context.Context, userID, newUsername, actor, reason string) (*storage.UserUsernameRepair, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if e := validateRepairIdentity("user ID", userID); e != nil {
		return nil, e
	}
	if e := identity.ValidateUsername(newUsername); e != nil {
		return nil, e
	}
	if e := validateRepairIdentity("repair actor", actor); e != nil {
		return nil, e
	}
	if e := validateRepairReason(reason); e != nil {
		return nil, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	old, e := lockUser(ctx, tx, userID)
	if e != nil {
		return nil, e
	}
	if e := s.validatePersistedRole(old.Role); e != nil {
		return nil, e
	}
	if identity.ValidateUsername(old.Username) == nil {
		return nil, fmt.Errorf("username for user ID %q is already canonical; use user rename", userID)
	}
	if old.CredentialEpoch >= uint64(1<<63-1) {
		return nil, storage.ErrCredentialEpochChanged
	}
	now := time.Now().UTC()
	if _, e = tx.ExecContext(ctx, rebind(`UPDATE users SET username=?,updated_at=?,credential_epoch=? WHERE id=?`), newUsername, now, old.CredentialEpoch+1, userID); e != nil {
		return nil, e
	}
	res, e := tx.ExecContext(ctx, rebind(`UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at IS NULL`), now, now, userID)
	if e != nil {
		return nil, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return nil, e
	}
	v := &storage.UserUsernameRepair{ID: uuid.NewString(), UserID: userID, OldUsername: old.Username, NewUsername: newUsername, Actor: actor, Reason: reason, RevokedSessions: n, CreatedAt: now}
	if _, e = tx.ExecContext(ctx, rebind(`INSERT INTO user_username_repairs(id,user_id,old_username,new_username,actor,reason,revoked_sessions,created_at) VALUES(?,?,?,?,?,?,?,?)`), v.ID, v.UserID, v.OldUsername, v.NewUsername, v.Actor, v.Reason, v.RevokedSessions, v.CreatedAt); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return v, nil
}
