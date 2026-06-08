package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create sqlite dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	if err := s.ensureColumns(ctx, "sites", map[string]string{
		"loadbalance": `ALTER TABLE sites ADD COLUMN loadbalance TEXT NOT NULL DEFAULT 'round_robin'`,
		"waf_enabled": `ALTER TABLE sites ADD COLUMN waf_enabled INTEGER NOT NULL DEFAULT 1`,
		"waf_mode":    `ALTER TABLE sites ADD COLUMN waf_mode TEXT NOT NULL DEFAULT 'block'`,
		"advanced":    `ALTER TABLE sites ADD COLUMN advanced TEXT NOT NULL DEFAULT '{}'`,
	}); err != nil {
		return fmt.Errorf("migrate sqlite columns: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ensureColumns(ctx context.Context, table string, migrations map[string]string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
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
	for column, statement := range migrations {
		if existing[column] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,advanced,enabled,created_at,updated_at FROM sites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		sites = append(sites, *site)
	}
	return sites, rows.Err()
}

func (s *SQLiteStore) GetSite(ctx context.Context, id string) (*Site, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,advanced,enabled,created_at,updated_at FROM sites WHERE id=?`, id)
	site, err := scanSite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return site, err
}

func (s *SQLiteStore) CreateSite(ctx context.Context, site *Site) error {
	ensureSite(site)
	domains, upstreams := encodeStrings(site.Domains), encodeStrings(site.Upstreams)
	advanced := encodeJSON(site.Advanced)
	_, err := s.db.ExecContext(ctx, `INSERT INTO sites(id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,advanced,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		site.ID, site.Name, domains, upstreams, site.ListenPort, site.LoadBalance, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.WAFEnabled), site.WAFMode, advanced, boolInt(site.Enabled), formatTime(site.CreatedAt), formatTime(site.UpdatedAt))
	return err
}

func (s *SQLiteStore) UpdateSite(ctx context.Context, site *Site) error {
	if site == nil {
		return fmt.Errorf("site is nil")
	}
	site.UpdatedAt = time.Now().UTC()
	domains, upstreams := encodeStrings(site.Domains), encodeStrings(site.Upstreams)
	advanced := encodeJSON(site.Advanced)
	_, err := s.db.ExecContext(ctx, `UPDATE sites SET name=?,domains=?,upstreams=?,listen_port=?,loadbalance=?,enable_ssl=?,cert_file=?,key_file=?,waf_enabled=?,waf_mode=?,advanced=?,enabled=?,updated_at=? WHERE id=?`,
		site.Name, domains, upstreams, site.ListenPort, site.LoadBalance, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.WAFEnabled), site.WAFMode, advanced, boolInt(site.Enabled), formatTime(site.UpdatedAt), site.ID)
	return err
}

func (s *SQLiteStore) DeleteSite(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) ListRules(ctx context.Context, siteID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,site_id,name,description,pattern,location,action,severity,enabled,priority FROM rules WHERE (?='' OR site_id=?) ORDER BY priority,id`, siteID, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, *rule)
	}
	return rules, rows.Err()
}

func (s *SQLiteStore) GetRule(ctx context.Context, id string) (*Rule, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,site_id,name,description,pattern,location,action,severity,enabled,priority FROM rules WHERE id=?`, id)
	rule, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return rule, err
}

func (s *SQLiteStore) CreateRule(ctx context.Context, rule *Rule) error {
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	if rule.Action == "" {
		rule.Action = "block"
	}
	if rule.Location == "" {
		rule.Location = "uri"
	}
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO rules(id,site_id,name,description,pattern,location,action,severity,enabled,priority) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		rule.ID, rule.SiteID, rule.Name, rule.Description, rule.Pattern, rule.Location, rule.Action, rule.Severity, boolInt(rule.Enabled), rule.Priority)
	return err
}

func (s *SQLiteStore) UpdateRule(ctx context.Context, rule *Rule) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rules SET site_id=?,name=?,description=?,pattern=?,location=?,action=?,severity=?,enabled=?,priority=? WHERE id=?`,
		rule.SiteID, rule.Name, rule.Description, rule.Pattern, rule.Location, rule.Action, rule.Severity, boolInt(rule.Enabled), rule.Priority, rule.ID)
	return err
}

func (s *SQLiteStore) DeleteRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at FROM users WHERE username=?`, username)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) CreateUser(ctx context.Context, user *User) error {
	ensureUser(user)
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		user.ID, user.Username, user.PasswordHash, user.Role, boolInt(user.TwoFAEnabled), user.TwoFASecret, formatTime(user.CreatedAt), formatTime(user.UpdatedAt))
	return err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE users SET username=?,password_hash=?,role=?,two_fa_enabled=?,two_fa_secret=?,updated_at=? WHERE id=?`,
		user.Username, user.PasswordHash, user.Role, boolInt(user.TwoFAEnabled), user.TwoFASecret, formatTime(user.UpdatedAt), user.ID)
	return err
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *user)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) CreateSession(ctx context.Context, session *Session) error {
	ensureSession(session)
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_sessions(id,user_id,username,role,issued_at,expires_at,revoked_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		session.ID, session.UserID, session.Username, session.Role, formatTime(session.IssuedAt), formatTime(session.ExpiresAt), formatOptionalTime(session.RevokedAt), formatTime(session.CreatedAt), formatTime(session.UpdatedAt))
	return err
}

func (s *SQLiteStore) RotateSession(ctx context.Context, oldID, userID string, next *Session) error {
	if oldID == "" || userID == "" {
		return fmt.Errorf("session id and user id are required")
	}
	ensureSession(next)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at=''`,
		formatOptionalTime(now), formatTime(now), oldID, userID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("session is not active")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_sessions(id,user_id,username,role,issued_at,expires_at,revoked_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		next.ID, next.UserID, next.Username, next.Role, formatTime(next.IssuedAt), formatTime(next.ExpiresAt), formatOptionalTime(next.RevokedAt), formatTime(next.CreatedAt), formatTime(next.UpdatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) RevokeSession(ctx context.Context, id, userID string) error {
	if id == "" || userID == "" {
		return fmt.Errorf("session id and user id are required")
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at=''`, formatOptionalTime(now), formatTime(now), id, userID)
	return err
}

func (s *SQLiteStore) RevokeUserSessions(ctx context.Context, userID string, exceptID string) error {
	if userID == "" {
		return fmt.Errorf("user id is required")
	}
	now := time.Now().UTC()
	query := `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at=''`
	args := []any{formatOptionalTime(now), formatTime(now), userID}
	if exceptID != "" {
		query += ` AND id<>?`
		args = append(args, exceptID)
	}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *SQLiteStore) IsSessionActive(ctx context.Context, id, userID string, now time.Time) (bool, error) {
	if id == "" || userID == "" {
		return false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM admin_sessions WHERE id=? AND user_id=? AND revoked_at='' AND expires_at>?`, id, userID, formatTime(now)).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLiteStore) PruneSessions(ctx context.Context, before time.Time) (int64, error) {
	if before.IsZero() {
		before = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at<? OR (revoked_at<>'' AND revoked_at<?)`, formatTime(before), formatOptionalTime(before))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSite(row scanner) (*Site, error) {
	var site Site
	var domains, upstreams, advanced, createdAt, updatedAt string
	var enableSSL, wafEnabled, enabled int
	if err := row.Scan(&site.ID, &site.Name, &domains, &upstreams, &site.ListenPort, &site.LoadBalance, &enableSSL, &site.CertFile, &site.KeyFile, &wafEnabled, &site.WAFMode, &advanced, &enabled, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	site.Domains = decodeStrings(domains)
	site.Upstreams = decodeStrings(upstreams)
	site.EnableSSL = enableSSL == 1
	site.WAFEnabled = wafEnabled == 1
	site.Advanced = decodeSiteAdvanced(advanced)
	site.Enabled = enabled == 1
	site.CreatedAt = parseTime(createdAt)
	site.UpdatedAt = parseTime(updatedAt)
	ensureSiteDefaults(&site)
	return &site, nil
}

func scanRule(row scanner) (*Rule, error) {
	var rule Rule
	var enabled int
	if err := row.Scan(&rule.ID, &rule.SiteID, &rule.Name, &rule.Description, &rule.Pattern, &rule.Location, &rule.Action, &rule.Severity, &enabled, &rule.Priority); err != nil {
		return nil, err
	}
	rule.Enabled = enabled == 1
	return &rule, nil
}

func scanUser(row scanner) (*User, error) {
	var user User
	var twoFA int
	var createdAt, updatedAt string
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &twoFA, &user.TwoFASecret, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	user.TwoFAEnabled = twoFA == 1
	user.CreatedAt = parseTime(createdAt)
	user.UpdatedAt = parseTime(updatedAt)
	return &user, nil
}

func ensureSite(site *Site) {
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

func ensureSiteDefaults(site *Site) {
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
	if site.WAFEnabled && !site.Advanced.Protection.SemanticSQL && !site.Advanced.Protection.SemanticXSS &&
		!site.Advanced.Protection.SemanticRCE && !site.Advanced.Protection.SemanticLFI &&
		!site.Advanced.Protection.SemanticXXE && !site.Advanced.Protection.SemanticSSRF &&
		!site.Advanced.Protection.SemanticNoSQL && !site.Advanced.Protection.SemanticSSTI {
		site.Advanced.Protection.SemanticSQL = true
		site.Advanced.Protection.SemanticXSS = true
		site.Advanced.Protection.SemanticRCE = true
		site.Advanced.Protection.SemanticLFI = true
		site.Advanced.Protection.SemanticXXE = true
		site.Advanced.Protection.SemanticSSRF = true
		site.Advanced.Protection.SemanticNoSQL = true
		site.Advanced.Protection.SemanticSSTI = true
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

func ensureUser(user *User) {
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

func ensureSession(session *Session) {
	now := time.Now().UTC()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = now
	}
	if session.IssuedAt.IsZero() {
		session.IssuedAt = now
	}
}

func encodeStrings(values []string) string {
	data, _ := json.Marshal(values)
	return string(data)
}

func encodeJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func decodeStrings(raw string) []string {
	var values []string
	_ = json.Unmarshal([]byte(raw), &values)
	return values
}

func decodeSiteAdvanced(raw string) SiteAdvanced {
	var value SiteAdvanced
	_ = json.Unmarshal([]byte(raw), &value)
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		value = time.Now().UTC()
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
