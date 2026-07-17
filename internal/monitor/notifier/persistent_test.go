package notifier

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestPersistAlertsIsUserScopedAndIdempotent(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "notifications.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, user := range []storage.User{{ID: "user-a", Username: "a", PasswordHash: "hash"}, {ID: "user-b", Username: "b", PasswordHash: "hash"}} {
		user := user
		if err := store.CreateUser(ctx, &user); err != nil {
			t.Fatal(err)
		}
	}
	alert := monitor.Alert{RuleID: "cpu-high", Name: "CPU high", Severity: "high", Message: "CPU usage exceeded threshold", StartsAt: time.Now().UTC()}
	if err := PersistAlerts(ctx, store, []monitor.Alert{alert}); err != nil {
		t.Fatal(err)
	}
	if err := PersistAlerts(ctx, store, []monitor.Alert{alert}); err != nil {
		t.Fatal(err)
	}
	for _, userID := range []string{"user-a", "user-b"} {
		items, total, filtered, unread, err := store.ListNotifications(ctx, userID, storage.NotificationFilter{State: "all", Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || filtered != 1 || unread != 1 || len(items) != 1 {
			t.Fatalf("unexpected notifications for %s: items=%+v total=%d filtered=%d unread=%d", userID, items, total, filtered, unread)
		}
		if items[0].Type != "critical" || items[0].Target != "/monitor" || items[0].Message != alert.Message {
			t.Fatalf("unexpected persisted alert for %s: %+v", userID, items[0])
		}
	}
}
