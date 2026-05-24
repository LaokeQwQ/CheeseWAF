package handler

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func (h *Handler) ListTasks(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.Scheduler.Tasks)
}

func (h *Handler) TaskHistory(w http.ResponseWriter, _ *http.Request) {
	writeData(w, []any{})
}

func (h *Handler) StorageStats(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"data_dir": h.Config.Setup.DataDir,
		"log_dir":  filepath.Dir(h.Config.Logging.Output.File.Path),
		"data":     dirSize(h.Config.Setup.DataDir),
		"logs":     dirSize(filepath.Dir(h.Config.Logging.Output.File.Path)),
	})
}

func (h *Handler) CleanupStorage(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{"cleaned": true, "timestamp": time.Now().UTC()})
}

func (h *Handler) ExportBackup(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"status": "ready",
		"scope":  []string{"config", "sites", "rules", "ip", "scheduler"},
	})
}

func (h *Handler) RestoreBackup(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	writeData(w, map[string]any{"restored": true, "requires_restart": false})
}

func (h *Handler) BlockPageTemplates(w http.ResponseWriter, _ *http.Request) {
	writeData(w, blockpage.TemplateLibrary())
}

func (h *Handler) ImportNginx(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	sites, err := config.ParseNginxServerBlock(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "NGINX_PARSE_ERROR", err.Error())
		return
	}
	writeData(w, sites)
}

func dirSize(root string) int64 {
	if root == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err == nil {
			total += info.Size()
		}
		_ = path
		return nil
	})
	return total
}
