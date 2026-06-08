package handler

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func (h *Handler) ListTasks(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.Scheduler.Tasks)
}

func (h *Handler) UpdateTasks(w http.ResponseWriter, r *http.Request) {
	var req []config.ScheduledTaskConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Scheduler.Tasks = req
	writeData(w, h.Config.Scheduler.Tasks)
}

func (h *Handler) TaskHistory(w http.ResponseWriter, _ *http.Request) {
	writeData(w, []any{})
}

func (h *Handler) EdgePolicy(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.Edge)
}

func (h *Handler) UpdateEdgePolicy(w http.ResponseWriter, r *http.Request) {
	var req config.EdgeConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Edge = req
	writeData(w, h.Config.Edge)
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

type reclaimPayload struct {
	Target string `json:"target"`
}

type reclaimAction struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func (h *Handler) ReclaimSystemResources(w http.ResponseWriter, r *http.Request) {
	req := reclaimPayload{Target: "memory"}
	if r.Body != nil && r.ContentLength != 0 {
		if !decode(w, r, &req) {
			return
		}
	}
	if req.Target == "" {
		req.Target = "memory"
	}
	if req.Target != "memory" && req.Target != "swap" && req.Target != "all" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "target must be memory, swap, or all")
		return
	}
	actions := reclaimResources(r.Context(), req.Target)
	ok := true
	for _, action := range actions {
		ok = ok && action.OK
	}
	writeData(w, map[string]any{
		"ok":        ok,
		"target":    req.Target,
		"actions":   actions,
		"timestamp": time.Now().UTC(),
	})
}

func reclaimResources(ctx context.Context, target string) []reclaimAction {
	actions := []reclaimAction{reclaimGoMemory()}
	if target == "memory" || target == "all" {
		actions = append(actions, reclaimKernelCaches(ctx)...)
	}
	if target == "swap" || target == "all" {
		actions = append(actions, reclaimSwap(ctx)...)
	}
	return actions
}

func reclaimGoMemory() reclaimAction {
	runtime.GC()
	debug.FreeOSMemory()
	return reclaimAction{Name: "go-runtime", OK: true, Message: "runtime GC and OS memory release requested"}
}

func reclaimKernelCaches(ctx context.Context) []reclaimAction {
	if runtime.GOOS != "linux" {
		return []reclaimAction{{Name: "kernel-page-cache", OK: false, Message: "kernel cache reclaim is only available on Linux"}}
	}
	actions := []reclaimAction{runMaintenanceCommand(ctx, "sync", "sync")}
	if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0o200); err != nil {
		actions = append(actions, reclaimAction{Name: "kernel-page-cache", OK: false, Message: err.Error()})
		return actions
	}
	actions = append(actions, reclaimAction{Name: "kernel-page-cache", OK: true, Message: "drop_caches=3 written"})
	return actions
}

func reclaimSwap(ctx context.Context) []reclaimAction {
	if runtime.GOOS != "linux" {
		return []reclaimAction{{Name: "swap-recycle", OK: false, Message: "swap recycle is only available on Linux"}}
	}
	off := runMaintenanceCommand(ctx, "swapoff", "swapoff", "-a")
	if !off.OK {
		return []reclaimAction{off}
	}
	on := runMaintenanceCommand(ctx, "swapon", "swapon", "-a")
	return []reclaimAction{off, on}
}

func runMaintenanceCommand(ctx context.Context, name string, command string, args ...string) reclaimAction {
	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(cmdCtx, command, args...).CombinedOutput()
	if err != nil {
		message := err.Error()
		if len(output) > 0 {
			message += ": " + string(output)
		}
		return reclaimAction{Name: name, OK: false, Message: message}
	}
	return reclaimAction{Name: name, OK: true, Message: string(output)}
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
