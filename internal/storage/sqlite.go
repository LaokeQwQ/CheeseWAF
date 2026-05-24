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
	return nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,domains,upstreams,listen_port,enable_ssl,cert_file,key_file,enabled,created_at,updated_at FROM sites ORDER BY name`)
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
	row := s.db.QueryRowContext(ctx, `SELECT id,name,domains,upstreams,listen_port,enable_ssl,cert_file,key_file,enabled,created_at,updated_at FROM sites WHERE id=?`, id)
	site, err := scanSite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return site, err
}

func (s *SQLiteStore) CreateSite(ctx context.Context, site *Site) error {
	ensureSite(site)
	domains, upstreams := encodeStrings(site.Domains), encodeStrings(site.Upstreams)
	_, err := s.db.ExecContext(ctx, `INSERT INTO sites(id,name,domains,upstreams,listen_port,enable_ssl,cert_file,key_file,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		site.ID, site.Name, domains, upstreams, site.ListenPort, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.Enabled), formatTime(site.CreatedAt), formatTime(site.UpdatedAt))
	return err
}

func (s *SQLiteStore) UpdateSite(ctx context.Context, site *Site) error {
	if site == nil {
		return fmt.Errorf("site is nil")
	}
	site.UpdatedAt = time.Now().UTC()
	domains, upstreams := encodeStrings(site.Domains), encodeStrings(site.Upstreams)
	_, err := s.db.ExecContext(ctx, `UPDATE sites SET name=?,domains=?,upstreams=?,listen_port=?,enable_ssl=?,cert_file=?,key_file=?,enabled=?,updated_at=? WHERE id=?`,
		site.Name, domains, upstreams, site.ListenPort, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.Enabled), formatTime(site.UpdatedAt), site.ID)
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

type scanner interface {
	Scan(dest ...any) error
}

func scanSite(row scanner) (*Site, error) {
	var site Site
	var domains, upstreams, createdAt, updatedAt string
	var enableSSL, enabled int
	if err := row.Scan(&site.ID, &site.Name, &domains, &upstreams, &site.ListenPort, &enableSSL, &site.CertFile, &site.KeyFile, &enabled, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	site.Domains = decodeStrings(domains)
	site.Upstreams = decodeStrings(upstreams)
	site.EnableSSL = enableSSL == 1
	site.Enabled = enabled == 1
	site.CreatedAt = parseTime(createdAt)
	site.UpdatedAt = parseTime(updatedAt)
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

func encodeStrings(values []string) string {
	data, _ := json.Marshal(values)
	return string(data)
}

func decodeStrings(raw string) []string {
	var values []string
	_ = json.Unmarshal([]byte(raw), &values)
	return values
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

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
