package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

const (
	sqliteBusyTimeoutMS       = 5000
	defaultReviewRetentionAge = 30 * 24 * time.Hour
	defaultReviewPruneBatch   = 500
)

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
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure sqlite pragmas: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) MarkTOTPConsumed(ctx context.Context, userID string, counter int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO totp_consumed(user_id, counter, expires_at, created_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(user_id, counter) DO UPDATE SET expires_at = excluded.expires_at,
		created_at = excluded.created_at`,
		userID, counter, expiresAt.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ConsumeTOTP atomically claims a TOTP counter. SQLite's single-statement
// UPSERT is serialized by the database (and this store also uses one pooled
// connection), so two independent store handles cannot both claim an active
// counter. An expired row is replaced and can be claimed again.
func (s *SQLiteStore) ConsumeTOTP(ctx context.Context, userID string, counter int64, expiresAt, now time.Time) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, errors.New("invalid sqlite store")
	}
	if userID == "" {
		return false, errors.New("user id is required")
	}
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if expiresAt.IsZero() {
		return false, errors.New("totp expiry is required")
	}
	if !expiresAt.After(now) {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO totp_consumed(user_id, counter, expires_at, created_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(user_id, counter) DO UPDATE SET expires_at = excluded.expires_at,
		created_at = excluded.created_at
		WHERE julianday(totp_consumed.expires_at) <= julianday(excluded.created_at)`,
		userID, counter, expiresAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *SQLiteStore) IsTOTPConsumed(ctx context.Context, userID string, counter int64, now time.Time) (bool, error) {
	var expiresAt string
	err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM totp_consumed WHERE user_id=? AND counter=?`, userID, counter).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return false, err
	}
	return expiry.After(now), nil
}

func (s *SQLiteStore) DeleteTOTPConsumed(ctx context.Context, userID string, counter int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_consumed WHERE user_id=? AND counter=?`, userID, counter)
	return err
}

func (s *SQLiteStore) PruneTOTPConsumed(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_consumed WHERE expires_at <= ?`, before.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,paranoia_level,advanced,enabled,created_at,updated_at FROM sites ORDER BY name`)
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
	row := s.db.QueryRowContext(ctx, `SELECT id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,paranoia_level,advanced,enabled,created_at,updated_at FROM sites WHERE id=?`, id)
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO sites(id,name,domains,upstreams,listen_port,loadbalance,enable_ssl,cert_file,key_file,waf_enabled,waf_mode,paranoia_level,advanced,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		site.ID, site.Name, domains, upstreams, site.ListenPort, site.LoadBalance, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.WAFEnabled), site.WAFMode, site.ParanoiaLevel, advanced, boolInt(site.Enabled), formatTime(site.CreatedAt), formatTime(site.UpdatedAt))
	return err
}

// NormalizeSiteForWrite applies the same defaulting used by the persistent
// store so API validation sees the effective site configuration.
func NormalizeSiteForWrite(site *Site) {
	ensureSite(site)
}

func (s *SQLiteStore) UpdateSite(ctx context.Context, site *Site) error {
	if site == nil {
		return fmt.Errorf("site is nil")
	}
	site.UpdatedAt = time.Now().UTC()
	domains, upstreams := encodeStrings(site.Domains), encodeStrings(site.Upstreams)
	advanced := encodeJSON(site.Advanced)
	_, err := s.db.ExecContext(ctx, `UPDATE sites SET name=?,domains=?,upstreams=?,listen_port=?,loadbalance=?,enable_ssl=?,cert_file=?,key_file=?,waf_enabled=?,waf_mode=?,paranoia_level=?,advanced=?,enabled=?,updated_at=? WHERE id=?`,
		site.Name, domains, upstreams, site.ListenPort, site.LoadBalance, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.WAFEnabled), site.WAFMode, site.ParanoiaLevel, advanced, boolInt(site.Enabled), formatTime(site.UpdatedAt), site.ID)
	return err
}

// RestoreSite replaces a site without advancing UpdatedAt. It is used only
// when a higher-level configuration mutation must compensate a failed commit.
func (s *SQLiteStore) RestoreSite(ctx context.Context, site *Site) error {
	if site == nil {
		return fmt.Errorf("site is nil")
	}
	domains, upstreams := encodeStrings(site.Domains), encodeStrings(site.Upstreams)
	advanced := encodeJSON(site.Advanced)
	_, err := s.db.ExecContext(ctx, `UPDATE sites SET name=?,domains=?,upstreams=?,listen_port=?,loadbalance=?,enable_ssl=?,cert_file=?,key_file=?,waf_enabled=?,waf_mode=?,paranoia_level=?,advanced=?,enabled=?,created_at=?,updated_at=? WHERE id=?`,
		site.Name, domains, upstreams, site.ListenPort, site.LoadBalance, boolInt(site.EnableSSL), site.CertFile, site.KeyFile, boolInt(site.WAFEnabled), site.WAFMode, site.ParanoiaLevel, advanced, boolInt(site.Enabled), formatTime(site.CreatedAt), formatTime(site.UpdatedAt), site.ID)
	return err
}

func (s *SQLiteStore) DeleteSite(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(err error) error {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM review_items WHERE site_id=?`, id); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM site_promotes WHERE site_id=?`, id); err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sites WHERE id=?`, id); err != nil {
		return rollback(err)
	}
	return tx.Commit()
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
	row := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch FROM users WHERE username=?`, username)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) CreateUser(ctx context.Context, user *User) error {
	if user == nil {
		return errors.New("user is nil")
	}
	if err := identity.ValidateUsername(user.Username); err != nil {
		return err
	}
	ensureUser(user)
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch) VALUES(?,?,?,?,?,?,?,?,?)`,
		user.ID, user.Username, user.PasswordHash, user.Role, boolInt(user.TwoFAEnabled), user.TwoFASecret, formatTime(user.CreatedAt), formatTime(user.UpdatedAt), user.CredentialEpoch)
	return err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, user *User) error {
	if user == nil {
		return errors.New("user is nil")
	}
	if err := identity.ValidateUsername(user.Username); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing User
	var twoFA int
	var createdAt, updatedAt string
	err = tx.QueryRowContext(ctx, `SELECT id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch FROM users WHERE id=?`, user.ID).Scan(&existing.ID, &existing.Username, &existing.PasswordHash, &existing.Role, &twoFA, &existing.TwoFASecret, &createdAt, &updatedAt, &existing.CredentialEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	}
	if err != nil {
		return err
	}
	existing.TwoFAEnabled = twoFA == 1
	existing.CreatedAt = parseTime(createdAt)
	existing.UpdatedAt = parseTime(updatedAt)
	if user.CredentialEpoch != existing.CredentialEpoch {
		return ErrCredentialEpochChanged
	}
	// A historical dirty account can only be repaired by the explicit
	// RepairUserUsername transaction, which records a reason and audit event.
	if err := identity.ValidateUsername(existing.Username); err != nil {
		return err
	}
	securityChanged := existing.Username != user.Username || existing.PasswordHash != user.PasswordHash || existing.Role != user.Role || existing.TwoFAEnabled != user.TwoFAEnabled || existing.TwoFASecret != user.TwoFASecret
	now := time.Now().UTC()
	nextEpoch := existing.CredentialEpoch
	if securityChanged {
		if nextEpoch == ^uint64(0) {
			return fmt.Errorf("%w: epoch exhausted", ErrCredentialEpochChanged)
		}
		nextEpoch++
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET username=?,password_hash=?,role=?,two_fa_enabled=?,two_fa_secret=?,updated_at=?,credential_epoch=? WHERE id=? AND credential_epoch=?`,
		user.Username, user.PasswordHash, user.Role, boolInt(user.TwoFAEnabled), user.TwoFASecret, formatTime(now), nextEpoch, user.ID, existing.CredentialEpoch)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrCredentialEpochChanged
	}
	if securityChanged {
		if _, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at=''`, formatOptionalTime(now), formatTime(now), user.ID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	user.UpdatedAt = now
	user.CredentialEpoch = nextEpoch
	return nil
}

// RepairUserUsername repairs one historical non-canonical username selected by
// immutable user ID. The rename, session revocation, and audit record commit as
// one transaction so a partially repaired identity cannot become visible.
func (s *SQLiteStore) RepairUserUsername(ctx context.Context, userID, newUsername, actor, reason string) (*UserUsernameRepair, error) {
	if err := validateRepairIdentity("user ID", userID); err != nil {
		return nil, err
	}
	if err := identity.ValidateUsername(newUsername); err != nil {
		return nil, err
	}
	if err := validateRepairIdentity("repair actor", actor); err != nil {
		return nil, err
	}
	if err := validateRepairReason(reason); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var oldUsername string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, userID).Scan(&oldUsername); errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user ID %q not found", userID)
	} else if err != nil {
		return nil, err
	}
	if identity.ValidateUsername(oldUsername) == nil {
		return nil, fmt.Errorf("username for user ID %q is already canonical; use user rename", userID)
	}
	var existingID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username=?`, newUsername).Scan(&existingID); err == nil {
		return nil, fmt.Errorf("user %q already exists", newUsername)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE users SET username=?,updated_at=? WHERE id=?`, newUsername, formatTime(now), userID)
	if err != nil {
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, fmt.Errorf("repair updated %d users, want 1", affected)
	}

	result, err = tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at=''`, formatOptionalTime(now), formatTime(now), userID)
	if err != nil {
		return nil, err
	}
	revoked, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	repair := &UserUsernameRepair{
		ID:              uuid.NewString(),
		UserID:          userID,
		OldUsername:     oldUsername,
		NewUsername:     newUsername,
		Actor:           actor,
		Reason:          reason,
		RevokedSessions: revoked,
		CreatedAt:       now,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_username_repairs(id,user_id,old_username,new_username,actor,reason,revoked_sessions,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		repair.ID, repair.UserID, repair.OldUsername, repair.NewUsername, repair.Actor, repair.Reason, repair.RevokedSessions, formatTime(repair.CreatedAt)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return repair, nil
}

func validateRepairIdentity(field, value string) error {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
		return fmt.Errorf("%s must be non-empty and contain only visible ASCII characters without whitespace", field)
	}
	return nil
}

func validateRepairReason(reason string) error {
	if !utf8.ValidString(reason) || strings.TrimSpace(reason) == "" {
		return errors.New("repair reason is required and must be valid UTF-8")
	}
	runes := []rune(reason)
	if len(runes) > 512 {
		return errors.New("repair reason must contain at most 512 characters")
	}
	for _, r := range runes {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("repair reason must not contain control or formatting characters")
		}
	}
	return nil
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch FROM users ORDER BY username`)
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

func (s *SQLiteStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,two_fa_enabled,two_fa_secret,created_at,updated_at,credential_epoch FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return user, err
}

func (s *SQLiteStore) CreateSession(ctx context.Context, session *Session) error {
	if session == nil {
		return errors.New("session is nil")
	}
	ensureSession(session)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentEpoch uint64
	if err := tx.QueryRowContext(ctx, `SELECT credential_epoch FROM users WHERE id=?`, session.UserID).Scan(&currentEpoch); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}
	if session.CredentialEpoch != currentEpoch {
		return ErrCredentialEpochChanged
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_sessions(id,user_id,username,role,issued_at,expires_at,revoked_at,created_at,updated_at,credential_epoch) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		session.ID, session.UserID, session.Username, session.Role, formatTime(session.IssuedAt), formatTime(session.ExpiresAt), formatOptionalTime(session.RevokedAt), formatTime(session.CreatedAt), formatTime(session.UpdatedAt), session.CredentialEpoch); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) RotateSession(ctx context.Context, oldID, userID string, next *Session) error {
	if oldID == "" || userID == "" {
		return fmt.Errorf("session id and user id are required")
	}
	if next == nil {
		return errors.New("session is nil")
	}
	if next.UserID != userID {
		return ErrCredentialEpochChanged
	}
	ensureSession(next)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var currentEpoch uint64
	if err := tx.QueryRowContext(ctx, `SELECT credential_epoch FROM users WHERE id=?`, userID).Scan(&currentEpoch); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}
	if next.CredentialEpoch != currentEpoch {
		return ErrCredentialEpochChanged
	}
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
		return ErrSessionNotFound
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO admin_sessions(id,user_id,username,role,issued_at,expires_at,revoked_at,created_at,updated_at,credential_epoch) SELECT ?,id,username,role,?,?,?,?,?,credential_epoch FROM users WHERE id=? AND username=? AND role=? AND credential_epoch=?`,
		next.ID, formatTime(next.IssuedAt), formatTime(next.ExpiresAt), formatOptionalTime(next.RevokedAt), formatTime(next.CreatedAt), formatTime(next.UpdatedAt), userID, next.Username, next.Role, next.CredentialEpoch)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrCredentialEpochChanged
	}
	next.CredentialEpoch = currentEpoch
	return tx.Commit()
}

func (s *SQLiteStore) RevokeSession(ctx context.Context, id, userID string) error {
	if id == "" || userID == "" {
		return fmt.Errorf("session id and user id are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=?`, userID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at=''`, formatOptionalTime(now), formatTime(now), id, userID)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrSessionNotFound
	}
	return tx.Commit()
}

func (s *SQLiteStore) RevokeUserSessions(ctx context.Context, userID string, exceptID string) error {
	if userID == "" {
		return fmt.Errorf("user id is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentEpoch uint64
	if err := tx.QueryRowContext(ctx, `SELECT credential_epoch FROM users WHERE id=?`, userID).Scan(&currentEpoch); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}
	if currentEpoch == ^uint64(0) {
		return fmt.Errorf("%w: epoch exhausted", ErrCredentialEpochChanged)
	}
	nextEpoch := currentEpoch + 1
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE users SET credential_epoch=?,updated_at=? WHERE id=? AND credential_epoch=?`, nextEpoch, formatTime(now), userID, currentEpoch)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrCredentialEpochChanged
	}
	query := `UPDATE admin_sessions SET revoked_at=?,updated_at=? WHERE user_id=? AND revoked_at=''`
	args := []any{formatOptionalTime(now), formatTime(now), userID}
	if exceptID != "" {
		query += ` AND id<>?`
		args = append(args, exceptID)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	if exceptID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET credential_epoch=?,updated_at=? WHERE id=? AND user_id=? AND revoked_at='' AND credential_epoch=?`, nextEpoch, formatTime(now), exceptID, userID, currentEpoch); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) IsSessionActive(ctx context.Context, id, userID string, now time.Time) (bool, error) {
	if id == "" || userID == "" {
		return false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM admin_sessions AS s JOIN users AS u ON u.id=s.user_id AND u.username=s.username AND u.role=s.role AND u.credential_epoch=s.credential_epoch WHERE s.id=? AND s.user_id=? AND s.revoked_at='' AND s.expires_at>?`, id, userID, formatTime(now)).Scan(&count)
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
	if err := row.Scan(&site.ID, &site.Name, &domains, &upstreams, &site.ListenPort, &site.LoadBalance, &enableSSL, &site.CertFile, &site.KeyFile, &wafEnabled, &site.WAFMode, &site.ParanoiaLevel, &advanced, &enabled, &createdAt, &updatedAt); err != nil {
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
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &twoFA, &user.TwoFASecret, &createdAt, &updatedAt, &user.CredentialEpoch); err != nil {
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
