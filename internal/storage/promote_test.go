package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSitePromoteRoundTrip(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	until := time.Date(2026, 8, 14, 12, 1, 0, 0, time.UTC)
	if err := store.UpsertSitePromote(ctx, "site-a", until); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSitePromote(ctx, "site-a", until.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.ListSitePromotes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded["site-a"]
	if !got.Equal(until.Add(time.Minute)) {
		t.Fatalf("upsert must replace deadline, got %v", got)
	}
	if err := store.DeleteSitePromote(ctx, "site-a"); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.ListSitePromotes(ctx)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("delete must clear row, got %#v err=%v", loaded, err)
	}
}
