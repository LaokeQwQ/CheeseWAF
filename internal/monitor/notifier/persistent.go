package notifier

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// PersistAlerts creates one durable notification per user and alert instance.
// The stable ID makes repeated evaluations of the same active alert idempotent.
func PersistAlerts(ctx context.Context, store storage.Store, alerts []monitor.Alert) error {
	if store == nil || len(alerts) == 0 {
		return nil
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list notification recipients: %w", err)
	}
	var persistErrors []error
	for _, user := range users {
		for _, alert := range alerts {
			notification := storage.Notification{
				ID:        alertNotificationID(user.ID, alert),
				UserID:    user.ID,
				Type:      notificationSeverity(alert.Severity),
				Title:     firstNonEmpty(strings.TrimSpace(alert.Name), strings.TrimSpace(alert.RuleID), "Security alert"),
				Message:   strings.TrimSpace(alert.Message),
				Target:    "/monitor",
				CreatedAt: alert.StartsAt.UTC(),
				UpdatedAt: alert.StartsAt.UTC(),
			}
			if err := store.CreateNotification(ctx, &notification); err != nil {
				persistErrors = append(persistErrors, fmt.Errorf("persist alert %q for user %q: %w", alert.RuleID, user.ID, err))
			}
		}
	}
	return errorsJoin(persistErrors)
}

func alertNotificationID(userID string, alert monitor.Alert) string {
	key := userID + "\x00" + alert.RuleID + "\x00" + alert.StartsAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("alert-%x", sum[:16])
}

func notificationSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "error", "fatal":
		return "critical"
	case "warning", "warn", "medium":
		return "warning"
	default:
		return "info"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
