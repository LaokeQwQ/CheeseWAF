package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *SQLiteStore) CreateNotification(ctx context.Context, notification *Notification) error {
	if notification == nil || strings.TrimSpace(notification.UserID) == "" || strings.TrimSpace(notification.Title) == "" {
		return fmt.Errorf("notification user id and title are required")
	}
	now := time.Now().UTC()
	if notification.ID == "" {
		notification.ID = uuid.NewString()
	}
	switch strings.ToLower(strings.TrimSpace(notification.Type)) {
	case "critical":
		notification.Type = "critical"
	case "warning":
		notification.Type = "warning"
	default:
		notification.Type = "info"
	}
	if notification.CreatedAt.IsZero() {
		notification.CreatedAt = now
	}
	if notification.UpdatedAt.IsZero() {
		notification.UpdatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO notifications(id,user_id,type,title,message,target,is_read,is_pinned,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		notification.ID, notification.UserID, notification.Type, notification.Title, notification.Message, notification.Target,
		boolInt(notification.Read), boolInt(notification.Pinned), formatTime(notification.CreatedAt), formatTime(notification.UpdatedAt))
	return err
}

func (s *SQLiteStore) ListNotifications(ctx context.Context, userID string, filter NotificationFilter) ([]Notification, int64, int64, int64, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, 0, 0, 0, fmt.Errorf("notification user id is required")
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	where, args, err := notificationWhere(userID, filter.State)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	var total, filteredTotal, unread int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1), COALESCE(SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END),0) FROM notifications WHERE user_id=?`, userID).Scan(&total, &unread); err != nil {
		return nil, 0, 0, 0, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM notifications WHERE `+where, args...).Scan(&filteredTotal); err != nil {
		return nil, 0, 0, 0, err
	}
	queryArgs := append(append([]any(nil), args...), filter.Limit, filter.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,type,title,message,target,is_read,is_pinned,created_at,updated_at FROM notifications WHERE `+where+` ORDER BY is_pinned DESC, created_at DESC, id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer rows.Close()
	items := make([]Notification, 0, filter.Limit)
	for rows.Next() {
		item, err := scanNotification(rows)
		if err != nil {
			return nil, 0, 0, 0, err
		}
		items = append(items, *item)
	}
	return items, total, filteredTotal, unread, rows.Err()
}

func (s *SQLiteStore) UpdateNotification(ctx context.Context, userID, id string, patch NotificationPatch) (*Notification, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("notification user id and id are required")
	}
	if patch.Read == nil && patch.Pinned == nil {
		return nil, fmt.Errorf("notification patch is empty")
	}
	sets := []string{"updated_at=?"}
	args := []any{formatTime(time.Now().UTC())}
	if patch.Read != nil {
		sets = append(sets, "is_read=?")
		args = append(args, boolInt(*patch.Read))
	}
	if patch.Pinned != nil {
		sets = append(sets, "is_pinned=?")
		args = append(args, boolInt(*patch.Pinned))
	}
	args = append(args, id, userID)
	result, err := s.db.ExecContext(ctx, `UPDATE notifications SET `+strings.Join(sets, ",")+` WHERE id=? AND user_id=?`, args...)
	if err != nil {
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, nil
	}
	return s.getNotification(ctx, userID, id)
}

func (s *SQLiteStore) MarkAllNotificationsRead(ctx context.Context, userID string) (int64, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, fmt.Errorf("notification user id is required")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE notifications SET is_read=1,updated_at=? WHERE user_id=? AND is_read=0`, formatTime(time.Now().UTC()), userID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *SQLiteStore) ClearNotifications(ctx context.Context, userID string) (int64, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, fmt.Errorf("notification user id is required")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE user_id=?`, userID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func notificationWhere(userID, state string) (string, []any, error) {
	where := "user_id=?"
	args := []any{userID}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "all":
	case "unread":
		where += " AND is_read=0"
	case "read":
		where += " AND is_read=1"
	case "pinned":
		where += " AND is_pinned=1"
	default:
		return "", nil, fmt.Errorf("invalid notification filter")
	}
	return where, args, nil
}

func (s *SQLiteStore) getNotification(ctx context.Context, userID, id string) (*Notification, error) {
	item, err := scanNotification(s.db.QueryRowContext(ctx, `SELECT id,user_id,type,title,message,target,is_read,is_pinned,created_at,updated_at FROM notifications WHERE id=? AND user_id=?`, id, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return item, err
}

func scanNotification(row scanner) (*Notification, error) {
	var item Notification
	var read, pinned int
	var createdAt, updatedAt string
	if err := row.Scan(&item.ID, &item.UserID, &item.Type, &item.Title, &item.Message, &item.Target, &read, &pinned, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	item.Read = read != 0
	item.Pinned = pinned != 0
	item.CreatedAt = parseTime(createdAt)
	item.UpdatedAt = parseTime(updatedAt)
	return &item, nil
}
