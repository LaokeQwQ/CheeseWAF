package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestStoreFeedItemPersistsNormalizedItem(t *testing.T) {
	ctx := context.Background()
	raw, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := storage.AsIntelStore(raw)
	if err != nil {
		t.Fatal(err)
	}
	source := feed.Source{ID: "feed-a", URL: "https://advisory.example.test/feed.xml", Enabled: true}
	item := feed.FeedItem{
		ExternalID: "CVE-2026-1", SourceID: source.ID, Title: "critical RCE",
		Summary: "advisory body", ContentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CVEIDs: []string{"CVE-2026-1"}, References: []string{"https://advisory.example.test/CVE-2026-1"},
	}
	created, err := storeFeedItem(ctx, store, source, item)
	if err != nil || !created {
		t.Fatalf("storeFeedItem created=%v err=%v", created, err)
	}
	items, err := store.ListItems(ctx, intelstore.ItemFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SourceID != source.ID || items[0].ContentHash != item.ContentHash {
		t.Fatalf("unexpected stored items: %+v", items)
	}
	if len(items[0].ExternalIDs) < 2 || items[0].RawExcerpt != item.Summary {
		t.Fatalf("feed metadata was not preserved: %+v", items[0])
	}
}
