package proxy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestPromoteTableArmsAndExpires(t *testing.T) {
	table := newPromoteTable()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	table.Arm("site-a", 10, now)
	if !table.Active("site-a", now.Add(9*time.Second)) {
		t.Fatal("expected active inside window")
	}
	if table.Active("site-a", now.Add(10*time.Second)) {
		t.Fatal("expected expired at deadline")
	}
	if table.Active("site-b", now) {
		t.Fatal("other site must stay inactive")
	}
}

func TestPromoteTableKeepsLaterDeadline(t *testing.T) {
	table := newPromoteTable()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	table.Arm("site-a", 30, now)
	table.Arm("site-a", 5, now.Add(time.Second))
	if !table.Active("site-a", now.Add(20*time.Second)) {
		t.Fatal("shorter later arm must not cut an existing longer window")
	}
}

func TestPromoteTablePersistsAcrossReload(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	first := newPromoteTable()
	first.SetStore(store)
	first.Arm("site-a", 60, now)

	reloaded := newPromoteTable()
	reloaded.SetStore(store)
	if !reloaded.Active("site-a", now.Add(30*time.Second)) {
		t.Fatal("promote window must survive process reload")
	}
	if reloaded.Active("site-a", now.Add(61*time.Second)) {
		t.Fatal("expired promote window must not stay active")
	}
	loaded, err := store.ListSitePromotes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded["site-a"]; ok {
		t.Fatalf("expired promote must be deleted, got %#v", loaded)
	}
}
