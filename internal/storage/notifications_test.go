package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteNotificationsAreUserScopedAndCounted(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "notifications.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, user := range []User{{ID: "user-a", Username: "a", PasswordHash: "hash"}, {ID: "user-b", Username: "b", PasswordHash: "hash"}} {
		user := user
		if err := store.CreateUser(ctx, &user); err != nil {
			t.Fatal(err)
		}
	}
	items := []*Notification{
		{ID: "a-unread", UserID: "user-a", Title: "A unread"},
		{ID: "a-read", UserID: "user-a", Title: "A read", Read: true},
		{ID: "a-pinned", UserID: "user-a", Title: "A pinned", Pinned: true},
		{ID: "b-only", UserID: "user-b", Title: "B only"},
	}
	for _, item := range items {
		if err := store.CreateNotification(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	got, total, filtered, unread, err := store.ListNotifications(ctx, "user-a", NotificationFilter{State: "unread", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || filtered != 2 || unread != 2 || len(got) != 2 || got[0].ID != "a-pinned" {
		t.Fatalf("unexpected list result: items=%+v total=%d filtered=%d unread=%d", got, total, filtered, unread)
	}
	read := true
	updated, err := store.UpdateNotification(ctx, "user-b", "a-unread", NotificationPatch{Read: &read})
	if err != nil || updated != nil {
		t.Fatalf("cross-user update must not find notification: item=%+v err=%v", updated, err)
	}
	deleted, err := store.ClearNotifications(ctx, "user-a")
	if err != nil || deleted != 3 {
		t.Fatalf("clear user-a: deleted=%d err=%v", deleted, err)
	}
	remaining, total, _, _, err := store.ListNotifications(ctx, "user-b", NotificationFilter{State: "all", Limit: 10})
	if err != nil || total != 1 || len(remaining) != 1 || remaining[0].ID != "b-only" {
		t.Fatalf("user-b notification was affected: items=%+v total=%d err=%v", remaining, total, err)
	}
}

func TestSQLiteNotificationsPaginationOrderingAndMutations(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "notifications.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user := User{ID: "user-a", Username: "a", PasswordHash: "hash"}
	if err := store.CreateUser(ctx, &user); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	for _, item := range []*Notification{
		{ID: "old", UserID: user.ID, Type: "info", Title: "Old", CreatedAt: base},
		{ID: "new", UserID: user.ID, Type: "warning", Title: "New", CreatedAt: base.Add(time.Minute)},
		{ID: "pinned", UserID: user.ID, Type: "critical", Title: "Pinned", Pinned: true, CreatedAt: base.Add(-time.Minute)},
	} {
		if err := store.CreateNotification(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	duplicate := &Notification{ID: "old", UserID: user.ID, Type: "critical", Title: "Duplicate must not overwrite", Read: true}
	if err := store.CreateNotification(ctx, duplicate); err != nil {
		t.Fatalf("idempotent duplicate create: %v", err)
	}
	invalidType := &Notification{ID: "normalized", UserID: user.ID, Type: "unexpected-css-class", Title: "Normalized"}
	if err := store.CreateNotification(ctx, invalidType); err != nil {
		t.Fatalf("create normalized notification: %v", err)
	}
	if invalidType.Type != "info" {
		t.Fatalf("invalid notification type must normalize to info, got %q", invalidType.Type)
	}
	page, total, filtered, unread, err := store.ListNotifications(ctx, user.ID, NotificationFilter{State: "all", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || filtered != 4 || unread != 4 || len(page) != 2 || page[0].ID != "pinned" || page[1].ID != "normalized" {
		t.Fatalf("unexpected first page: items=%+v total=%d filtered=%d unread=%d", page, total, filtered, unread)
	}
	page, _, _, _, err = store.ListNotifications(ctx, user.ID, NotificationFilter{State: "all", Offset: 2, Limit: 2})
	if err != nil || len(page) != 2 || page[0].ID != "new" || page[1].ID != "old" {
		t.Fatalf("unexpected second page: items=%+v err=%v", page, err)
	}
	read, pinned := true, false
	updated, err := store.UpdateNotification(ctx, user.ID, "pinned", NotificationPatch{Read: &read, Pinned: &pinned})
	if err != nil || updated == nil || !updated.Read || updated.Pinned {
		t.Fatalf("update notification: item=%+v err=%v", updated, err)
	}
	count, err := store.MarkAllNotificationsRead(ctx, user.ID)
	if err != nil || count != 3 {
		t.Fatalf("mark all read: count=%d err=%v", count, err)
	}
}
