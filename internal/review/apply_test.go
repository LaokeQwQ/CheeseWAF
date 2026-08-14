package review

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestHighConfidenceRequiresModelAndHighRisk(t *testing.T) {
	if HighConfidence("high", false) {
		t.Fatal("heuristic-only must not auto-agree")
	}
	if HighConfidence("low", true) {
		t.Fatal("low risk must not auto-agree")
	}
	if !HighConfidence("high", true) || !HighConfidence("critical", true) {
		t.Fatal("high/critical model verdict should auto-agree")
	}
}

func TestAddPayloadRuleAndAutoAgree(t *testing.T) {
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	site := &storage.Site{Name: "site-a", Domains: []string{"a.test"}, Upstreams: []string{"127.0.0.1:9"}, Enabled: true}
	if err := store.CreateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	item := &storage.ReviewItem{
		SiteID:   site.ID,
		URI:      "/search",
		Category: "webshell",
		Payload:  "eval($_GET[cmd])",
		Source:   "query",
		Status:   "pending",
	}
	if err := store.CreateReviewItem(ctx, item); err != nil {
		t.Fatal(err)
	}
	q := &Queue{
		Store:     store,
		AutoAgree: func(string) bool { return true },
		ApplyBlock: func(ctx context.Context, item *storage.ReviewItem) (string, error) {
			return AddPayloadRule(ctx, store, item)
		},
	}
	q.maybeAutoAgree(ctx, item, &ai.AttackAnalysis{Risk: "high", AIUsed: true, Summary: "php gadget"})
	got, err := store.GetReviewItem(ctx, item.ID)
	if err != nil || got == nil || got.Status != "blocked" || got.Decision != "block_payload" {
		t.Fatalf("auto-agree: %+v err=%v", got, err)
	}
	updated, err := store.GetSite(ctx, site.ID)
	if err != nil || updated == nil || len(updated.Advanced.CustomRules) != 1 {
		t.Fatalf("expected live rule, site=%+v err=%v", updated, err)
	}
}
