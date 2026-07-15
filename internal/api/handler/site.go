package handler

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

func (h *Handler) ListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, sitesView(sites))
}

func (h *Handler) GetSite(w http.ResponseWriter, r *http.Request) {
	site, err := h.Store.GetSite(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if site == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "site not found")
		return
	}
	writeData(w, siteView(*site))
}

func (h *Handler) CreateSite(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	var site storage.Site
	if !decode(w, r, &site) {
		return
	}
	storage.NormalizeSiteForWrite(&site)
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		return append(sites, site)
	}); err != nil {
		writeError(w, http.StatusBadRequest, "SITE_INVALID", err.Error())
		return
	}
	if err := h.Store.CreateSite(r.Context(), &site); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSitesOrRollback(r, func() error {
		return h.Store.DeleteSite(r.Context(), site.ID)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	writeData(w, siteView(site))
}

func (h *Handler) UpdateSite(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	var site storage.Site
	if !decode(w, r, &site) {
		return
	}
	site.ID = chi.URLParam(r, "id")
	storage.NormalizeSiteForWrite(&site)
	existing, err := h.Store.GetSite(r.Context(), site.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "site not found")
		return
	}
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		for index := range sites {
			if sites[index].ID == site.ID {
				sites[index] = site
				return sites
			}
		}
		return append(sites, site)
	}); err != nil {
		writeError(w, http.StatusBadRequest, "SITE_INVALID", err.Error())
		return
	}
	if err := h.Store.UpdateSite(r.Context(), &site); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSitesOrRollback(r, func() error {
		if restorer, ok := h.Store.(interface {
			RestoreSite(context.Context, *storage.Site) error
		}); ok {
			return restorer.RestoreSite(r.Context(), existing)
		}
		return h.Store.UpdateSite(r.Context(), existing)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	writeData(w, siteView(site))
}

func (h *Handler) DeleteSite(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	h.siteMutationMu.Lock()
	defer h.siteMutationMu.Unlock()
	siteID := chi.URLParam(r, "id")
	existing, err := h.Store.GetSite(r.Context(), siteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "site not found")
		return
	}
	if err := h.validateCandidateSites(r, func(sites []storage.Site) []storage.Site {
		out := make([]storage.Site, 0, len(sites))
		for _, site := range sites {
			if site.ID != siteID {
				out = append(out, site)
			}
		}
		return out
	}); err != nil {
		writeError(w, http.StatusBadRequest, "SITE_INVALID", err.Error())
		return
	}
	if err := h.Store.DeleteSite(r.Context(), siteID); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSitesOrRollback(r, func() error {
		return h.Store.CreateSite(r.Context(), existing)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	writeData(w, map[string]bool{"deleted": true})
}

func (h *Handler) syncSitesOrRollback(r *http.Request, rollback func() error) error {
	err := h.syncSites(r)
	if err == nil || rollback == nil {
		return err
	}
	if rollbackErr := rollback(); rollbackErr != nil {
		h.configMutationMu.Lock()
		h.freezeConfigWritesLocked(fmt.Sprintf("site sync failed: %v; site store rollback failed: %v", err, rollbackErr))
		h.configMutationMu.Unlock()
		return fmt.Errorf("%w; rollback site store: %v", err, rollbackErr)
	}
	return err
}

func (h *Handler) syncSites(r *http.Request) error {
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		return err
	}
	configSites := storage.SitesToConfig(sites)
	_, err = h.commitConfigMutation(func(candidate *config.Config) error {
		candidate.Sites = configSites
		return nil
	}, func(candidate *config.Config) error {
		if h.OnSitesChanged == nil {
			return nil
		}
		return h.OnSitesChanged(candidate.Sites)
	})
	return err
}

func (h *Handler) validateCandidateSites(r *http.Request, mutate func([]storage.Site) []storage.Site) error {
	if h == nil || h.Store == nil || h.Config == nil {
		return nil
	}
	current, err := h.Store.ListSites(r.Context())
	if err != nil {
		return err
	}
	candidate := mutate(append([]storage.Site(nil), current...))
	if len(candidate) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	next := *h.Config
	next.Sites = storage.SitesToConfig(candidate)
	if err := config.Validate(&next); err != nil {
		return err
	}
	return nil
}

func (h *Handler) persistConfig() error {
	if h != nil {
		h.configMutationMu.Lock()
		defer h.configMutationMu.Unlock()
		if ok, reason := h.clusterConfigWritable("zh-CN"); !ok {
			return fmt.Errorf("cluster protection mode: %s", reason)
		}
		if h.configWriteFrozen {
			return fmt.Errorf("configuration writes are frozen: %s", h.configFreezeReason)
		}
	}
	return h.persistConfigLocked()
}

func (h *Handler) persistConfigLocked() error {
	if h == nil || h.Config == nil || h.ConfigPath == "" {
		return nil
	}
	return h.persistConfigCandidateLocked(h.Config)
}

func (h *Handler) persistConfigCandidateLocked(candidate *config.Config) error {
	if h == nil || candidate == nil || h.ConfigPath == "" {
		return nil
	}
	if _, err := config.EnsureRuntimeSecrets(candidate); err != nil {
		return err
	}
	if err := config.Validate(candidate); err != nil {
		return err
	}
	previous, err := os.ReadFile(h.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read previous config: %w", err)
	}
	if err := config.Save(h.ConfigPath, candidate); err != nil {
		return err
	}
	if len(previous) == 0 {
		return nil
	}
	if err := h.writeConfigVersion(previous, candidate); err != nil {
		if rollbackErr := writeConfigBytesAtomic(h.ConfigPath, previous); rollbackErr != nil {
			h.freezeConfigWritesLocked(fmt.Sprintf("version save failed: %v; config rollback failed: %v", err, rollbackErr))
			return fmt.Errorf("save config version: %w; rollback config: %v", err, rollbackErr)
		}
		return fmt.Errorf("save config version: %w", err)
	}
	return nil
}

func (h *Handler) writeConfigVersion(raw []byte, candidate *config.Config) error {
	if h.ConfigPath == "" {
		return nil
	}
	now := h.nowUTC()
	if err := writeConfigVersionFile(filepath.Join(filepath.Dir(h.ConfigPath), "versions"), raw, now); err == nil {
		return nil
	}
	if candidate != nil && candidate.Setup.RuntimeDir != "" {
		return writeConfigVersionFile(filepath.Join(candidate.Setup.RuntimeDir, "versions"), raw, now)
	}
	return fmt.Errorf("no writable config version directory")
}

func writeConfigVersionFile(dir string, raw []byte, now time.Time) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := "cheesewaf-" + now.UTC().Format("20060102T150405Z") + ".yaml"
	return os.WriteFile(filepath.Join(dir, name), raw, 0o640)
}

func writeConfigBytesAtomic(path string, raw []byte) error {
	var cfg config.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("decode rollback config: %w", err)
	}
	return config.Save(path, &cfg)
}

func (h *Handler) freezeConfigWritesLocked(reason string) {
	h.configWriteFrozen = true
	h.configFreezeReason = strings.TrimSpace(reason)
	if h.configFreezeReason == "" {
		h.configFreezeReason = "configuration state could not be restored"
	}
}

func (h *Handler) commitConfigMutation(mutate func(*config.Config) error, applyRuntime func(*config.Config) error) (*config.Config, error) {
	h.configMutationMu.Lock()
	defer h.configMutationMu.Unlock()
	if h.configWriteFrozen {
		return nil, fmt.Errorf("configuration writes are frozen: %s", h.configFreezeReason)
	}
	if ok, reason := h.clusterConfigWritable("zh-CN"); !ok {
		return nil, fmt.Errorf("cluster protection mode: %s", reason)
	}
	candidate, err := config.Clone(h.Config)
	if err != nil {
		return nil, err
	}
	if err := mutate(candidate); err != nil {
		return nil, err
	}
	if _, err := config.EnsureRuntimeSecrets(candidate); err != nil {
		return nil, err
	}
	if err := config.Validate(candidate); err != nil {
		return nil, err
	}
	if applyRuntime != nil {
		if err := applyRuntime(candidate); err != nil {
			if rollbackErr := applyRuntime(h.Config); rollbackErr != nil {
				h.freezeConfigWritesLocked(fmt.Sprintf("runtime apply failed: %v; runtime rollback failed: %v", err, rollbackErr))
				return nil, fmt.Errorf("apply runtime config: %w; rollback runtime config: %v", err, rollbackErr)
			}
			return nil, fmt.Errorf("apply runtime config: %w", err)
		}
	}
	if err := h.persistConfigCandidateLocked(candidate); err != nil {
		if applyRuntime != nil {
			if rollbackErr := applyRuntime(h.Config); rollbackErr != nil {
				h.freezeConfigWritesLocked(fmt.Sprintf("config save failed: %v; runtime rollback failed: %v", err, rollbackErr))
				return nil, fmt.Errorf("save config: %w; rollback runtime config: %v", err, rollbackErr)
			}
		}
		return nil, err
	}
	*h.Config = *candidate
	return candidate, nil
}
