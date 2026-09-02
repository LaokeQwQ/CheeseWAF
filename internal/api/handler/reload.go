package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// ReloadLiveConfig applies the file-backed settings that the running process
// can actually hot-apply (sites, edge, protection, API security, block page,
// time sync). Listen addresses, TLS files, storage backends, and other
// restart-only fields stay on the previous snapshot so APIs do not report them
// as live. Store site replacement is restored as a whole if any write fails.
func (h *Handler) ReloadLiveConfig(next *config.Config) error {
	if h == nil {
		return fmt.Errorf("handler is unavailable")
	}
	if next == nil {
		return fmt.Errorf("reloaded config is nil")
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	h.configPersistMu.Lock()
	defer h.configPersistMu.Unlock()
	h.configMutationMu.Lock()
	defer h.configMutationMu.Unlock()
	if h.configWriteFrozen {
		return fmt.Errorf("configuration writes are frozen: %s", h.configFreezeReason)
	}
	if ok, reason := h.clusterConfigWritable("zh-CN"); !ok {
		return fmt.Errorf("cluster protection mode: %s", reason)
	}
	previous, err := config.Clone(h.currentConfig())
	if err != nil {
		return err
	}
	loaded, err := config.Clone(next)
	if err != nil {
		return err
	}
	if _, err := config.EnsureRuntimeSecrets(loaded); err != nil {
		return err
	}
	if err := config.Validate(loaded); err != nil {
		return err
	}
	overlay, err := overlayHotReloadConfig(previous, loaded)
	if err != nil {
		return err
	}
	if err := config.Validate(overlay); err != nil {
		return err
	}
	if err := h.applyLiveRuntime(overlay); err != nil {
		if rollbackErr := h.applyLiveRuntime(previous); rollbackErr != nil {
			h.freezeConfigWritesLocked(fmt.Sprintf("file reload apply failed: %v; runtime rollback failed: %v", err, rollbackErr))
			return fmt.Errorf("apply reloaded config: %w; rollback runtime config: %v", err, rollbackErr)
		}
		return fmt.Errorf("apply reloaded config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.replaceStoreSites(ctx, overlay.Sites); err != nil {
		if rollbackErr := h.applyLiveRuntime(previous); rollbackErr != nil {
			h.freezeConfigWritesLocked(fmt.Sprintf("file reload store sync failed: %v; runtime rollback failed: %v", err, rollbackErr))
			return fmt.Errorf("sync reloaded sites: %w; rollback runtime config: %v", err, rollbackErr)
		}
		return fmt.Errorf("sync reloaded sites: %w", err)
	}
	return h.publishConfig(overlay)
}

func overlayHotReloadConfig(live, loaded *config.Config) (*config.Config, error) {
	if live == nil || loaded == nil {
		return nil, fmt.Errorf("configuration is unavailable")
	}
	overlay, err := config.Clone(loaded)
	if err != nil {
		return nil, err
	}
	overlay.Deployment = live.Deployment
	overlay.Server = live.Server
	overlay.TLS = live.TLS
	overlay.Setup = live.Setup
	overlay.Cluster = live.Cluster
	overlay.Console = live.Console
	overlay.CAPTCHAAssets = live.CAPTCHAAssets
	overlay.Storage = live.Storage
	overlay.Logging = live.Logging
	overlay.ACME = live.ACME
	overlay.AI = live.AI
	overlay.Update = live.Update
	overlay.Vulnerability = live.Vulnerability
	overlay.Scheduler = live.Scheduler
	overlay.Monitor = live.Monitor
	overlay.Performance = live.Performance
	preserveSystemSecrets(*live, overlay)
	return overlay, nil
}

func (h *Handler) applyLiveRuntime(candidate *config.Config) error {
	if candidate == nil {
		return fmt.Errorf("configuration is unavailable")
	}
	if h.OnSitesChanged != nil {
		if err := h.OnSitesChanged(candidate.Sites); err != nil {
			return err
		}
	}
	if h.OnEdgeChanged != nil {
		if err := h.OnEdgeChanged(candidate.Edge); err != nil {
			return err
		}
	}
	if h.OnProtectionChanged != nil {
		if err := h.OnProtectionChanged(candidate.Protection); err != nil {
			return err
		}
	}
	if h.OnAPISecChanged != nil {
		if err := h.OnAPISecChanged(candidate.APISec); err != nil {
			return err
		}
	}
	if h.OnBlockPageChanged != nil {
		if err := h.OnBlockPageChanged(candidate.BlockPage); err != nil {
			return err
		}
	}
	if h.OnTimeSyncChanged != nil {
		if err := h.OnTimeSyncChanged(candidate.TimeSync); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) replaceStoreSites(ctx context.Context, sites []config.SiteConfig) error {
	if h == nil || h.Store == nil {
		return nil
	}
	current, err := h.Store.ListSites(ctx)
	if err != nil {
		return err
	}
	snapshot, err := cloneStoredSites(current)
	if err != nil {
		return err
	}
	if err := h.applyStoreSiteReplacement(ctx, snapshot, sites); err != nil {
		if restoreErr := h.restoreStoreSites(ctx, snapshot); restoreErr != nil {
			h.freezeConfigWritesLocked(fmt.Sprintf("file reload store sync failed: %v; site store restore failed: %v", err, restoreErr))
			return fmt.Errorf("sync reloaded sites: %w; restore site store: %v", err, restoreErr)
		}
		return err
	}
	return nil
}

func (h *Handler) applyStoreSiteReplacement(ctx context.Context, current []storage.Site, sites []config.SiteConfig) error {
	currentByID := make(map[string]storage.Site, len(current))
	for _, site := range current {
		currentByID[site.ID] = site
	}
	keep := make(map[string]struct{}, len(sites))
	for _, cfgSite := range sites {
		stored := storage.SiteFromConfig(cfgSite)
		keep[stored.ID] = struct{}{}
		if existing, ok := currentByID[stored.ID]; ok {
			stored.CreatedAt = existing.CreatedAt
			if err := h.Store.UpdateSite(ctx, &stored); err != nil {
				return err
			}
			continue
		}
		if err := h.Store.CreateSite(ctx, &stored); err != nil {
			return err
		}
	}
	for id, existing := range currentByID {
		if _, ok := keep[id]; ok {
			continue
		}
		if err := h.Store.DeleteSite(ctx, existing.ID); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) restoreStoreSites(ctx context.Context, snapshot []storage.Site) error {
	current, err := h.Store.ListSites(ctx)
	if err != nil {
		return err
	}
	currentByID := make(map[string]struct{}, len(current))
	for _, site := range current {
		currentByID[site.ID] = struct{}{}
	}
	snapshotByID := make(map[string]struct{}, len(snapshot))
	for index := range snapshot {
		site := snapshot[index]
		snapshotByID[site.ID] = struct{}{}
		if _, exists := currentByID[site.ID]; exists {
			if err := h.restoreStoredSite(ctx, &site); err != nil {
				return err
			}
			continue
		}
		if err := h.Store.CreateSite(ctx, &site); err != nil {
			return err
		}
	}
	for _, site := range current {
		if _, keep := snapshotByID[site.ID]; keep {
			continue
		}
		if err := h.Store.DeleteSite(ctx, site.ID); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) restoreStoredSite(ctx context.Context, site *storage.Site) error {
	if restorer, ok := h.Store.(interface {
		RestoreSite(context.Context, *storage.Site) error
	}); ok {
		return restorer.RestoreSite(ctx, site)
	}
	return h.Store.UpdateSite(ctx, site)
}

func cloneStoredSites(sites []storage.Site) ([]storage.Site, error) {
	out := make([]storage.Site, 0, len(sites))
	for index := range sites {
		cloned, err := cloneSite(&sites[index])
		if err != nil {
			return nil, err
		}
		out = append(out, *cloned)
	}
	return out, nil
}
