package handler

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

const maxConfigVersionFiles = 20

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
	// GET redacts KeyPEM and ACME env values; empty client fields mean "keep existing".
	preserveSiteSecrets(existing, &site)
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
		if err := h.preservePersistedRestartOnlyConfig(candidate); err != nil {
			return err
		}
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

// preservePersistedRestartOnlyConfig keeps file values that are intentionally
// waiting for process restart when a site-only API mutation writes the whole
// configuration document from the live snapshot.
func (h *Handler) preservePersistedRestartOnlyConfig(candidate *config.Config) error {
	if h == nil || candidate == nil || strings.TrimSpace(h.ConfigPath) == "" {
		return nil
	}
	disk, err := config.Load(h.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load persisted restart-only configuration: %w", err)
	}
	candidate.Deployment = disk.Deployment
	candidate.Server = disk.Server
	candidate.TLS = disk.TLS
	candidate.Setup = disk.Setup
	candidate.Cluster = disk.Cluster
	candidate.Console = disk.Console
	candidate.CAPTCHAAssets = disk.CAPTCHAAssets
	candidate.Storage = disk.Storage
	candidate.Logging = disk.Logging
	candidate.ACME = disk.ACME
	candidate.AI = disk.AI
	candidate.Update = disk.Update
	candidate.Vulnerability = disk.Vulnerability
	candidate.Scheduler = disk.Scheduler
	candidate.Monitor = disk.Monitor
	candidate.Performance = disk.Performance
	return nil
}

func (h *Handler) validateCandidateSites(r *http.Request, mutate func([]storage.Site) []storage.Site) error {
	if h == nil || h.Store == nil || h.currentConfig() == nil {
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
	next := *h.currentConfig()
	next.Sites = storage.SitesToConfig(candidate)
	if err := config.Validate(&next); err != nil {
		return err
	}
	return nil
}

// ConfigReadMiddleware is retained as a routing compatibility hook. Request
// handlers read immutable atomic snapshots, so long-lived GETs such as SSE and
// WebSocket connections must not hold the mutation lock for their lifetime.
func (h *Handler) ConfigReadMiddleware(next http.Handler) http.Handler {
	return next
}

func (h *Handler) persistConfig() error {
	if h != nil {
		h.configPersistMu.Lock()
		defer h.configPersistMu.Unlock()
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
	if h == nil || h.currentConfig() == nil || h.ConfigPath == "" {
		return nil
	}
	return h.persistConfigCandidateLocked(h.currentConfig())
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
	contents, err := redactConfigVersion(raw)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := pruneConfigVersionFiles(dir, maxConfigVersionFiles-1); err != nil {
		return err
	}
	// Include nanoseconds so same-second commits cannot overwrite history.
	name := "cheesewaf-" + now.UTC().Format("20060102T150405.000000000Z") + ".yaml"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(contents)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func redactConfigVersion(raw []byte) ([]byte, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode config version: %w", err)
	}
	redactConfigVersionNode(&document)
	contents, err := yaml.Marshal(&document)
	if err != nil {
		return nil, fmt.Errorf("encode redacted config version: %w", err)
	}
	return contents, nil
}

func redactConfigVersionNode(node *yaml.Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			redactConfigVersionNode(child)
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			value := node.Content[index+1]
			if configVersionSecretKey(key.Value) {
				value.Kind = yaml.ScalarNode
				value.Tag = "!!str"
				value.Value = ""
				value.Content = nil
				continue
			}
			redactConfigVersionNode(value)
		}
	}
}

func configVersionSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "env" || key == "headers" || key == "dsn" || key == "password" || key == "secret" || key == "token" || key == "hash" || key == "key_pem" || key == "jwks_json" {
		return true
	}
	return strings.HasSuffix(key, "_key") || strings.HasSuffix(key, "_secret") || strings.HasSuffix(key, "_password") || strings.HasSuffix(key, "_token") || strings.HasSuffix(key, "_hash")
}

func pruneConfigVersionFiles(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	versions := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "cheesewaf-") && strings.HasSuffix(entry.Name(), ".yaml") {
			versions = append(versions, entry)
		}
	}
	sort.Slice(versions, func(left, right int) bool { return versions[left].Name() < versions[right].Name() })
	if keep < 0 {
		keep = 0
	}
	for _, entry := range versions[:max(0, len(versions)-keep)] {
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
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
	h.configPersistMu.Lock()
	defer h.configPersistMu.Unlock()
	h.configMutationMu.Lock()
	defer h.configMutationMu.Unlock()
	if h.configWriteFrozen {
		return nil, fmt.Errorf("configuration writes are frozen: %s", h.configFreezeReason)
	}
	if ok, reason := h.clusterConfigWritable("zh-CN"); !ok {
		return nil, fmt.Errorf("cluster protection mode: %s", reason)
	}
	// Keep an independent previous snapshot for rollback; do not rely on h.currentConfig()
	// after applyRuntime may have mutated shared nested pointers.
	previous, err := config.Clone(h.currentConfig())
	if err != nil {
		return nil, err
	}
	candidate, err := config.Clone(h.currentConfig())
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
			if rollbackErr := applyRuntime(previous); rollbackErr != nil {
				h.freezeConfigWritesLocked(fmt.Sprintf("runtime apply failed: %v; runtime rollback failed: %v", err, rollbackErr))
				return nil, fmt.Errorf("apply runtime config: %w; rollback runtime config: %v", err, rollbackErr)
			}
			return nil, fmt.Errorf("apply runtime config: %w", err)
		}
	}
	if err := h.persistConfigCandidateLocked(candidate); err != nil {
		if applyRuntime != nil {
			if rollbackErr := applyRuntime(previous); rollbackErr != nil {
				h.freezeConfigWritesLocked(fmt.Sprintf("config save failed: %v; runtime rollback failed: %v", err, rollbackErr))
				return nil, fmt.Errorf("save config: %w; rollback runtime config: %v", err, rollbackErr)
			}
		}
		return nil, err
	}
	if err := h.publishConfig(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}
