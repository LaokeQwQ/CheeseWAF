package cli

import (
	"context"
	"log"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

// syncIntelSources registers the configured feeds and revokes every stored
// source that is no longer configured. Import permission is decided from the
// stored enabled rows, so leaving removed rows untouched would let a source
// deleted from intel.sources keep importing after a restart.
func syncIntelSources(ctx context.Context, sources []config.IntelSourceConfig, store intelstore.Store) {
	configured := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		configured[source.ID] = struct{}{}
		if err := store.UpsertSource(ctx, intel.Source{
			ID: source.ID, Type: source.Type, URL: source.URL,
			Trust: intel.ParseTrustLevel(source.Trust), Enabled: source.Enabled,
		}); err != nil {
			log.Printf("intel: register source %q: %v", source.ID, err)
		}
	}
	stored, err := store.ListSources(ctx)
	if err != nil {
		log.Printf("intel: reconcile sources: %v", err)
		return
	}
	for _, source := range stored {
		if !source.Enabled {
			continue
		}
		if _, ok := configured[source.ID]; ok {
			continue
		}
		source.Enabled = false
		if err := store.UpsertSource(ctx, source); err != nil {
			log.Printf("intel: revoke source %q: %v", source.ID, err)
		}
	}
}
