package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
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

func TestReviewListUsesSearchAndStableKeysetBoundaries(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	for _, id := range []string{"a", "c", "b"} {
		item := &ReviewItem{
			ID:          id,
			TraceID:     "trace-" + id,
			SiteID:      "site-a",
			ClientIP:    "203.0.113." + fmt.Sprint(len(id)),
			URI:         "/search/" + id,
			Category:    "webshell",
			Payload:     "needle-" + id,
			ParamName:   "parameter-" + id,
			Fingerprint: "fingerprint-" + id,
			Status:      "pending",
			CreatedAt:   createdAt,
		}
		if err := store.CreateReviewItem(ctx, item); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	first, total, err := store.ListReviewItems(ctx, ReviewFilter{Search: "needle", Limit: 2})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if total != 3 || len(first) != 2 || first[0].ID != "c" || first[1].ID != "b" {
		t.Fatalf("first page total=%d items=%+v", total, first)
	}
	next, _, err := store.ListReviewItems(ctx, ReviewFilter{
		Search:        "needle",
		WatermarkTime: first[0].CreatedAt,
		WatermarkID:   first[0].ID,
		BeforeTime:    first[1].CreatedAt,
		BeforeID:      first[1].ID,
		Limit:         2,
	})
	if err != nil {
		t.Fatalf("next page: %v", err)
	}
	if len(next) != 1 || next[0].ID != "a" {
		t.Fatalf("next page crossed or duplicated keyset boundary: %+v", next)
	}
	fingerprint, total, err := store.ListReviewItems(ctx, ReviewFilter{Search: "fingerprint-a", Limit: 2})
	if err != nil || total != 1 || len(fingerprint) != 1 || fingerprint[0].ID != "a" {
		t.Fatalf("fingerprint search total=%d items=%+v err=%v", total, fingerprint, err)
	}
}

func TestReviewListKeysetNormalizesRFC3339FractionalPrecision(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	for _, item := range []ReviewItem{
		{ID: "zero", Status: "pending", CreatedAt: base},
		{ID: "tenth", Status: "pending", CreatedAt: base.Add(100 * time.Millisecond)},
		{ID: "eleven", Status: "pending", CreatedAt: base.Add(110 * time.Millisecond)},
	} {
		item := item
		if err := store.CreateReviewItem(ctx, &item); err != nil {
			t.Fatalf("create %s: %v", item.ID, err)
		}
	}
	first, total, err := store.ListReviewItems(ctx, ReviewFilter{Limit: 2})
	if err != nil || total != 3 || len(first) != 2 || first[0].ID != "eleven" || first[1].ID != "tenth" {
		t.Fatalf("fractional first page total=%d items=%+v err=%v", total, first, err)
	}
	next, _, err := store.ListReviewItems(ctx, ReviewFilter{
		WatermarkTime: first[0].CreatedAt,
		WatermarkID:   first[0].ID,
		BeforeTime:    first[1].CreatedAt,
		BeforeID:      first[1].ID,
		Limit:         2,
	})
	if err != nil || len(next) != 1 || next[0].ID != "zero" {
		t.Fatalf("fractional next page items=%+v err=%v", next, err)
	}
}

func TestReviewListKeysetSupportsIDOnlyCursors(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		item := &ReviewItem{ID: id, Status: "pending", CreatedAt: time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)}
		if err := store.CreateReviewItem(ctx, item); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	items, _, err := store.ListReviewItems(ctx, ReviewFilter{BeforeID: "c", Limit: 10})
	if err != nil || len(items) != 2 || items[0].ID != "b" || items[1].ID != "a" {
		t.Fatalf("before id-only cursor items=%+v err=%v", items, err)
	}
	items, _, err = store.ListReviewItems(ctx, ReviewFilter{AfterID: "a", Limit: 10})
	if err != nil || len(items) != 2 || items[0].ID != "c" || items[1].ID != "b" {
		t.Fatalf("after id-only cursor items=%+v err=%v", items, err)
	}
}

func TestReviewItemBlockedAcceptsLastingDecision(t *testing.T) {
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
		URI:      "/search",
		Category: "webshell",
		Payload:  "eval($_GET[cmd])",
		Status:   "blocked",
		Decision: "block_now",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	got, err := store.DecideReviewItem(ctx, item.ID, ReviewDecision{Decision: "block_fingerprint", AppliedRuleID: "fingerprint:aabb"})
	if err != nil || got == nil || got.Decision != "block_fingerprint" || got.Status != "blocked" {
		t.Fatalf("blocked item must accept lasting intercept: %+v err=%v", got, err)
	}
	denied, err := store.DecideReviewItem(ctx, item.ID, ReviewDecision{Decision: "allow"})
	if err != nil || denied != nil {
		t.Fatalf("blocked item must reject allow, got %+v err=%v", denied, err)
	}
}

func TestReviewItemPendingDedupAndAIVerdict(t *testing.T) {
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
		SiteID:    "site-a",
		URI:       "/search",
		Category:  "webshell",
		Payload:   "eval($_GET[cmd])",
		Source:    "query",
		ParamName: "s",
		Status:    "pending",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	pending, err := store.HasPendingReview(ctx, "site-a", "webshell", "eval($_GET[cmd])", "/search")
	if err != nil || !pending {
		t.Fatalf("expected pending match, pending=%v err=%v", pending, err)
	}
	other, err := store.HasPendingReview(ctx, "site-a", "sqli", "eval($_GET[cmd])", "/search")
	if err != nil || other {
		t.Fatalf("different category should not match, pending=%v err=%v", other, err)
	}
	if err := store.SetReviewAIVerdict(ctx, item.ID, `{"risk":"high","summary":"php gadget","ai_used":false}`); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetReviewItem(ctx, item.ID)
	if err != nil || got == nil || got.AIVerdict == "" || got.ParamName != "s" {
		t.Fatalf("verdict/param: %+v err=%v", got, err)
	}
}

func TestReviewItemFingerprintPersists(t *testing.T) {
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
		SiteID:      "site-a",
		URI:         "/search",
		Category:    "webshell",
		Payload:     "eval($_GET[cmd])",
		Fingerprint: "aabbccddeeff0011",
		Status:      "pending",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetReviewItem(ctx, item.ID)
	if err != nil || got == nil || got.Fingerprint != "aabbccddeeff0011" {
		t.Fatalf("fingerprint persist: %+v err=%v", got, err)
	}
	similar, err := store.HasSimilarReview(ctx, "site-a", "webshell", "eval($_GET[cmd])", "/search")
	if err != nil || !similar {
		t.Fatalf("expected similar review, similar=%v err=%v", similar, err)
	}
}

func TestSiteParanoiaLevelPersists(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	site := &Site{Name: "example", Domains: []string{"example.test"}, Upstreams: []string{"127.0.0.1:9000"}, ParanoiaLevel: 5, Enabled: true}
	if err := store.CreateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetSite(ctx, site.ID)
	if err != nil || got == nil || got.ParanoiaLevel != 5 {
		t.Fatalf("create persist: %+v err=%v", got, err)
	}
	got.ParanoiaLevel = 0
	if err := store.UpdateSite(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, err := store.GetSite(ctx, site.ID)
	if err != nil || again == nil || again.ParanoiaLevel != 0 {
		t.Fatalf("level 0 must persist: %+v err=%v", again, err)
	}
}
