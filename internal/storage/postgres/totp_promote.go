package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ConsumeTOTP atomically claims a TOTP counter. PostgreSQL's unique key and
// conditional UPSERT make the claim safe across processes and connections:
// only an insert or replacement of an expired row returns a result row.
func (s *Store) ConsumeTOTP(ctx context.Context, userID string, counter int64, expiresAt, now time.Time) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" {
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
	var claimed bool
	err := s.row(ctx, `INSERT INTO totp_consumed(user_id,counter,expires_at,created_at)
		VALUES(?,?,?,?)
		ON CONFLICT(user_id,counter) DO UPDATE SET expires_at=EXCLUDED.expires_at,
		created_at=EXCLUDED.created_at
		WHERE totp_consumed.expires_at <= EXCLUDED.created_at
		RETURNING TRUE`, userID, counter, expiresAt, now).Scan(&claimed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return claimed, err
}

func (s *Store) MarkTOTPConsumed(ctx context.Context, userID string, counter int64, expiresAt time.Time) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("user id is required")
	}
	_, e := s.exec(ctx, "INSERT INTO totp_consumed(user_id,counter,expires_at,created_at) VALUES(?,?,?,?) ON CONFLICT(user_id,counter) DO UPDATE SET expires_at=EXCLUDED.expires_at,created_at=EXCLUDED.created_at", userID, counter, expiresAt.UTC(), time.Now().UTC())
	return e
}
func (s *Store) IsTOTPConsumed(ctx context.Context, userID string, counter int64, now time.Time) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" {
		return false, errors.New("user id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var found bool
	e := s.row(ctx, "SELECT EXISTS(SELECT 1 FROM totp_consumed WHERE user_id=? AND counter=? AND expires_at>?)", userID, counter, now).Scan(&found)
	return found, e
}
func (s *Store) DeleteTOTPConsumed(ctx context.Context, userID string, counter int64) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	_, e := s.exec(ctx, "DELETE FROM totp_consumed WHERE user_id=? AND counter=?", userID, counter)
	return e
}
func (s *Store) PruneTOTPConsumed(ctx context.Context, before time.Time) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	_, e := s.exec(ctx, "DELETE FROM totp_consumed WHERE expires_at<=?", before.UTC())
	return e
}
func (s *Store) UpsertSitePromote(ctx context.Context, siteID string, until time.Time) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if strings.TrimSpace(siteID) == "" || until.IsZero() {
		return errors.New("site promote requires site id and deadline")
	}
	_, e := s.exec(ctx, "INSERT INTO site_promotes(site_id,until_at) VALUES(?,?) ON CONFLICT(site_id) DO UPDATE SET until_at=EXCLUDED.until_at", strings.TrimSpace(siteID), until.UTC())
	return e
}
func (s *Store) ListSitePromotes(ctx context.Context) (map[string]time.Time, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	rows, e := s.query(ctx, "SELECT site_id,until_at FROM site_promotes")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var until dbTime
		if e := rows.Scan(&id, &until); e != nil {
			return nil, e
		}
		out[id] = until.Time
	}
	return out, rows.Err()
}
func (s *Store) DeleteSitePromote(ctx context.Context, siteID string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	_, e := s.exec(ctx, "DELETE FROM site_promotes WHERE site_id=?", strings.TrimSpace(siteID))
	return e
}
