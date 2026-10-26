package cli

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	monitornotify "github.com/LaokeQwQ/CheeseWAF/internal/monitor/notifier"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/index"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/notifierpack"
)

// defaultPluginIndexDir is used when plugins.index_dir is empty. It sits under
// the data directory so a package installed next to the service is picked up
// without a second path to keep in sync.
const defaultPluginIndexDir = "plugins"

// pluginIndexRuntime owns the local plugin index, the watcher that reloads it,
// and the notifier registry whose pack table follows the index. The registry
// pointer is shared with the managers built at startup, so a reload changes
// behaviour for the next notifier construction without a restart.
type pluginIndexRuntime struct {
	registry *monitornotify.Registry
	watcher  *index.Watcher
}

// resolvePluginIndexDir returns an absolute index directory. A relative
// plugins.index_dir is resolved against the data directory.
func resolvePluginIndexDir(cfg *config.Config, dataDir string) string {
	dir := ""
	if cfg != nil {
		dir = strings.TrimSpace(cfg.Plugins.IndexDir)
	}
	if dir == "" {
		dir = defaultPluginIndexDir
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	return filepath.Clean(filepath.Join(dataDir, dir))
}

// startPluginIndex scans the directory once, then watches it. A malformed
// package is reported and skipped; it never keeps the service from starting.
func startPluginIndex(ctx context.Context, cfg *config.Config, dataDir, hostVersion string) *pluginIndexRuntime {
	runtime := &pluginIndexRuntime{registry: monitornotify.NewRegistry()}
	dir := resolvePluginIndexDir(cfg, dataDir)
	interval := time.Duration(0)
	if cfg != nil {
		interval = cfg.Plugins.WatchInterval
	}
	load := func(snapshot *index.Snapshot) {
		if snapshot == nil {
			return
		}
		if err := runtime.registry.ReplacePacks(notifierPackFactories(snapshot, hostVersion)); err != nil {
			log.Printf("plugin index %q: %v", snapshot.Dir, err)
		}
		for _, entry := range snapshot.Problems() {
			if _, err := notifierpack.Parse(entry.Raw); err == nil {
				// A valid pack is not a problem just because it is not a CRP
				// manifest.
				continue
			}
			log.Printf("plugin index %q: %s: %v", snapshot.Dir, entry.Path, entry.Err)
		}
	}
	runtime.watcher = index.NewWatcher(dir, hostVersion, interval, load)
	runtime.watcher.Start(ctx)
	load(runtime.watcher.Snapshot())
	return runtime
}

// Registry returns the shared notifier registry.
func (r *pluginIndexRuntime) Registry() *monitornotify.Registry {
	if r == nil {
		return nil
	}
	return r.registry
}

// Close stops the watcher.
func (r *pluginIndexRuntime) Close() {
	if r == nil || r.watcher == nil {
		return
	}
	_ = r.watcher.Close()
}

// notifierPackFactories turns every loadable notifier pack in the snapshot into
// a registry factory. Binary and CRP packages are ignored here: they are
// activated through the CRP runtime, not through the notifier registry.
func notifierPackFactories(snapshot *index.Snapshot, hostVersion string) map[string]monitornotify.PackFactory {
	factories := make(map[string]monitornotify.PackFactory)
	if snapshot == nil {
		return factories
	}
	for _, entry := range snapshot.Entries {
		if len(entry.Raw) == 0 {
			continue
		}
		// A pack is recognised by its own schema, not by the CRP manifest
		// result: the two formats share a directory.
		pack, err := notifierpack.Parse(entry.Raw)
		if err != nil {
			continue
		}
		if err := pack.CheckHost(hostVersion); err != nil {
			log.Printf("plugin index: %s: %v", entry.Path, err)
			continue
		}
		loaded := pack
		factories[pack.Type] = func(cfg config.NotifierConfig) (monitornotify.Notifier, error) {
			deliverer, err := loaded.New(cfg, nil)
			if err != nil {
				return nil, fmt.Errorf("notifier pack %q: %w", loaded.ProviderID, err)
			}
			return deliverer, nil
		}
	}
	return factories
}
