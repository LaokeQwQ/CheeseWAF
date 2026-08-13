package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReviewItemCreateListDecide(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	item := &ReviewItem{
		SiteID:   "site-a",
		URI:      "/search?q=eval($_GET[cmd])",
		Category: "webshell",
		Payload:  "eval($_GET[cmd])",
		Shape:    "isolated",
		Status:   "pending",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	listed, total, err := store.ListReviewItems(ctx, ReviewFilter{SiteID: "site-a", Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(listed) != 1 || listed[0].URI != item.URI {
		t.Fatalf("list: total=%d items=%+v", total, listed)
	}
	decided, err := store.DecideReviewItem(ctx, item.ID, ReviewDecision{
		Decision:         "block_payload",
		DecidedBySubject: "u1",
		DecidedByName:    "admin",
		DecidedByRole:    "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decided == nil || decided.Status != "blocked" || decided.DecidedByName != "admin" {
		t.Fatalf("decide: %+v", decided)
	}
	again, err := store.DecideReviewItem(ctx, item.ID, ReviewDecision{Decision: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if again != nil {
		t.Fatalf("second decide should be a no-op, got %+v", again)
	}
}
