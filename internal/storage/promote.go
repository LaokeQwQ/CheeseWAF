package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *SQLiteStore) UpsertSitePromote(ctx context.Context, siteID string, until time.Time) error {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" || until.IsZero() {
		return fmt.Errorf("site promote requires site id and deadline")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO site_promotes(site_id, until_at) VALUES(?,?)
		ON CONFLICT(site_id) DO UPDATE SET until_at=excluded.until_at`, siteID, formatTime(until.UTC()))
	return err
}

func (s *SQLiteStore) ListSitePromotes(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT site_id, until_at FROM site_promotes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var siteID, until string
		if err := rows.Scan(&siteID, &until); err != nil {
			return nil, err
		}
		if t := parseTime(until); !t.IsZero() {
			out[siteID] = t
		}
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteSitePromote(ctx context.Context, siteID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM site_promotes WHERE site_id=?`, strings.TrimSpace(siteID))
	return err
}
