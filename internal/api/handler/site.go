package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, sites)
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
	writeData(w, site)
}

func (h *Handler) CreateSite(w http.ResponseWriter, r *http.Request) {
	var site storage.Site
	if !decode(w, r, &site) {
		return
	}
	if err := h.Store.CreateSite(r.Context(), &site); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSites(r); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	writeData(w, site)
}

func (h *Handler) UpdateSite(w http.ResponseWriter, r *http.Request) {
	var site storage.Site
	if !decode(w, r, &site) {
		return
	}
	site.ID = chi.URLParam(r, "id")
	if err := h.Store.UpdateSite(r.Context(), &site); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSites(r); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	writeData(w, site)
}

func (h *Handler) DeleteSite(w http.ResponseWriter, r *http.Request) {
	if err := h.Store.DeleteSite(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if err := h.syncSites(r); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SYNC_ERROR", err.Error())
		return
	}
	writeData(w, map[string]bool{"deleted": true})
}

func (h *Handler) syncSites(r *http.Request) error {
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		return err
	}
	configSites := storage.SitesToConfig(sites)
	if len(configSites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	h.Config.Sites = configSites
	if err := h.persistConfig(); err != nil {
		return err
	}
	if h.OnSitesChanged != nil {
		h.OnSitesChanged(configSites)
	}
	return nil
}

func (h *Handler) persistConfig() error {
	if h == nil || h.Config == nil || h.ConfigPath == "" {
		return nil
	}
	if _, err := config.EnsureRuntimeSecrets(h.Config); err != nil {
		return err
	}
	if err := config.Validate(h.Config); err != nil {
		return err
	}
	_ = h.writeConfigVersion()
	return config.Save(h.ConfigPath, h.Config)
}

func (h *Handler) writeConfigVersion() error {
	if h.ConfigPath == "" {
		return nil
	}
	raw, err := os.ReadFile(h.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	if err := writeConfigVersionFile(filepath.Join(filepath.Dir(h.ConfigPath), "versions"), raw); err == nil {
		return nil
	}
	if h.Config != nil && h.Config.Setup.RuntimeDir != "" {
		_ = writeConfigVersionFile(filepath.Join(h.Config.Setup.RuntimeDir, "versions"), raw)
	}
	return nil
}

func writeConfigVersionFile(dir string, raw []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := "cheesewaf-" + time.Now().UTC().Format("20060102T150405Z") + ".yaml"
	return os.WriteFile(filepath.Join(dir, name), raw, 0o640)
}
