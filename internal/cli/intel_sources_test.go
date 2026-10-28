package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// Removing a source from intel.sources must revoke its stored permission;
// otherwise the importer keeps trusting a host the operator deleted.
func TestSyncIntelSourcesRevokesRemovedSources(t *testing.T) {
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
	removed := intel.Source{ID: "old-feed", Type: "url", URL: "https://old.example.test/feed.xml", Trust: intel.TrustCommunity, Enabled: true}
	if err := store.UpsertSource(ctx, removed); err != nil {
		t.Fatal(err)
	}
	kept := config.IntelSourceConfig{ID: "new-feed", Type: "url", URL: "https://new.example.test/feed.xml", Trust: "community", Enabled: true}
	if err := syncIntelSources(ctx, []config.IntelSourceConfig{kept}, store); err != nil {
		t.Fatalf("sync sources: %v", err)
	}

	sources, err := store.ListSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]intel.Source, len(sources))
	for _, source := range sources {
		byID[source.ID] = source
	}
	if got := byID["old-feed"]; got.Enabled {
		t.Fatalf("removed source stayed enabled: %+v", got)
	}
	if got := byID["new-feed"]; !got.Enabled {
		t.Fatalf("configured source was not registered: %+v", got)
	}
}

// A failed reconciliation must surface so startup can keep URL imports off;
// silently logging would leave a removed source authorized.
func TestSyncIntelSourcesReportsFailure(t *testing.T) {
	ctx := context.Background()
	raw, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.AsIntelStore(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syncIntelSources(ctx, nil, store); err == nil {
		t.Fatal("closed store must report a reconciliation failure")
	}
}
