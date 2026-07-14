package handler

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/scheduler"
)

type scheduledTaskResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Schedule  string    `json:"schedule"`
	Every     string    `json:"every"`
	Frequency string    `json:"frequency"`
	At        string    `json:"at"`
	Target    string    `json:"target"`
	Channel   string    `json:"channel"`
	Recipient string    `json:"recipient"`
	Period    string    `json:"period"`
	Format    string    `json:"format"`
	Keep      int       `json:"keep"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type scheduledTaskPayload struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Type      string           `json:"type"`
	Schedule  string           `json:"schedule"`
	Every     flexibleDuration `json:"every"`
	Frequency string           `json:"frequency"`
	At        string           `json:"at"`
	Target    string           `json:"target"`
	Channel   string           `json:"channel"`
	Recipient string           `json:"recipient"`
	Period    string           `json:"period"`
	Format    string           `json:"format"`
	Keep      int              `json:"keep"`
	Enabled   bool             `json:"enabled"`
	CreatedAt time.Time        `json:"created_at"`
}

type flexibleDuration time.Duration

func (h *Handler) ListTasks(w http.ResponseWriter, _ *http.Request) {
	tasks := h.normalizedTaskConfigs()
	writeData(w, scheduledTaskResponses(tasks))
}

func (h *Handler) UpdateTasks(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	payload, ok := decodeScheduledTaskPayload(w, r)
	if !ok {
		return
	}
	req := make([]config.ScheduledTaskConfig, 0, len(payload))
	for _, item := range payload {
		req = append(req, item.config())
	}
	for index := range req {
		normalizeScheduledTask(&req[index])
	}
	if err := h.validateSchedulerTasks(req); err != nil {
		writeError(w, http.StatusBadRequest, "SCHEDULER_TASK_INVALID", err.Error())
		return
	}
	for _, task := range req {
		if !scheduler.SupportedTaskType(task.Type) {
			writeError(w, http.StatusBadRequest, "SCHEDULER_TASK_TYPE_UNSUPPORTED", "unsupported scheduler task type: "+task.Type)
			return
		}
	}
	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		candidate.Scheduler.Tasks = req
		return nil
	}, func(candidate *config.Config) error {
		engine := scheduler.Active()
		if engine == nil {
			return nil
		}
		tasks := scheduler.FromConfigWithRuntime(candidate.Scheduler, candidate.Setup.DataDir, h.ConfigPath, candidate.Logging.Output.File.Path, engine.Runtime())
		return engine.Replace(tasks)
	})
	if err != nil {
		code := "CONFIG_SAVE_ERROR"
		if strings.Contains(err.Error(), "apply runtime config:") {
			code = "SCHEDULER_RELOAD_ERROR"
		}
		writeError(w, http.StatusInternalServerError, code, err.Error())
		return
	}
	writeData(w, scheduledTaskResponses(committed.Scheduler.Tasks))
}

func (h *Handler) validateSchedulerTasks(tasks []config.ScheduledTaskConfig) error {
	if h == nil || h.Config == nil {
		return nil
	}
	candidate := *h.Config
	candidate.Scheduler.Tasks = tasks
	return config.Validate(&candidate)
}

func decodeScheduledTaskPayload(w http.ResponseWriter, r *http.Request) ([]scheduledTaskPayload, bool) {
	var raw json.RawMessage
	if !decode(w, r, &raw) {
		return nil, false
	}
	var payload []scheduledTaskPayload
	if err := json.Unmarshal(raw, &payload); err == nil {
		return payload, true
	}
	var wrapped struct {
		Tasks []scheduledTaskPayload `json:"tasks"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "scheduler tasks must be an array or {\"tasks\":[...]}")
		return nil, false
	}
	return wrapped.Tasks, true
}

func (payload scheduledTaskPayload) config() config.ScheduledTaskConfig {
	return config.ScheduledTaskConfig{
		ID:        payload.ID,
		Name:      payload.Name,
		Type:      payload.Type,
		Schedule:  payload.Schedule,
		Every:     time.Duration(payload.Every),
		Frequency: payload.Frequency,
		At:        payload.At,
		Target:    payload.Target,
		Channel:   payload.Channel,
		Recipient: payload.Recipient,
		Period:    payload.Period,
		Format:    payload.Format,
		Keep:      payload.Keep,
		Enabled:   payload.Enabled,
		CreatedAt: payload.CreatedAt,
	}
}

func (d *flexibleDuration) UnmarshalJSON(raw []byte) error {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == `""` {
		*d = 0
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if strings.TrimSpace(text) == "" {
			*d = 0
			return nil
		}
		if nanos, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64); err == nil {
			*d = flexibleDuration(time.Duration(nanos))
			return nil
		}
		parsed, err := parseTaskDuration(text)
		if err != nil {
			return err
		}
		*d = flexibleDuration(parsed)
		return nil
	}
	var nanos int64
	if err := json.Unmarshal(raw, &nanos); err != nil {
		return err
	}
	*d = flexibleDuration(time.Duration(nanos))
	return nil
}

func parseTaskDuration(value string) (time.Duration, error) {
	text := strings.TrimSpace(strings.ToLower(value))
	if text == "" {
		return 0, nil
	}
	if strings.HasSuffix(text, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(text, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(text)
}

func (d flexibleDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(durationForJSON(time.Duration(d)))
}

func (h *Handler) TaskHistory(w http.ResponseWriter, _ *http.Request) {
	engine := scheduler.Active()
	if engine == nil {
		writeData(w, []scheduler.HistoryEntry{})
		return
	}
	writeData(w, engine.History())
}

func (h *Handler) EdgePolicy(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.Edge)
}

func (h *Handler) UpdateEdgePolicy(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.EdgeConfig
	if !decode(w, r, &req) {
		return
	}
	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		candidate.Edge = req
		return nil
	}, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, committed.Edge)
}

func (h *Handler) StorageStats(w http.ResponseWriter, _ *http.Request) {
	logDir := filepath.Dir(h.Config.Logging.Output.File.Path)
	writeData(w, map[string]any{
		"data_dir": h.Config.Setup.DataDir,
		"log_dir":  logDir,
		"data":     h.cachedDirSize(h.Config.Setup.DataDir),
		"logs":     h.cachedDirSize(logDir),
	})
}

func (h *Handler) CleanupStorage(w http.ResponseWriter, _ *http.Request) {
	task := storageCleanupTask(h.Config)
	result, err := scheduler.CleanupOldFilesWithResult(scheduler.Task{
		ID:     task.ID,
		Name:   task.Name,
		Type:   task.Type,
		Target: task.Target,
		Keep:   task.Keep,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORAGE_CLEANUP_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{
		"cleaned":   true,
		"target":    result.Target,
		"keep":      result.Keep,
		"scanned":   result.Scanned,
		"removed":   result.Removed,
		"timestamp": time.Now().UTC(),
	})
}

func storageCleanupTask(cfg *config.Config) config.ScheduledTaskConfig {
	if cfg != nil {
		for _, task := range cfg.Scheduler.Tasks {
			if task.Type == "cleanup" {
				normalizeScheduledTask(&task)
				return task
			}
		}
		logDir := filepath.Dir(cfg.Logging.Output.File.Path)
		if strings.TrimSpace(logDir) != "" && logDir != "." {
			return config.ScheduledTaskConfig{
				ID:      "log-cleanup",
				Name:    "Log cleanup",
				Type:    "cleanup",
				Target:  logDir,
				Keep:    14,
				Enabled: true,
			}
		}
	}
	return config.ScheduledTaskConfig{
		ID:      "log-cleanup",
		Name:    "Log cleanup",
		Type:    "cleanup",
		Target:  "./logs",
		Keep:    14,
		Enabled: true,
	}
}

func normalizeScheduledTask(task *config.ScheduledTaskConfig) {
	task.ID = strings.TrimSpace(task.ID)
	task.Name = strings.TrimSpace(task.Name)
	task.Type = strings.TrimSpace(task.Type)
	task.Schedule = strings.TrimSpace(task.Schedule)
	task.Frequency = strings.TrimSpace(task.Frequency)
	task.At = strings.TrimSpace(task.At)
	task.Target = strings.TrimSpace(task.Target)
	task.Channel = strings.TrimSpace(task.Channel)
	task.Recipient = strings.TrimSpace(task.Recipient)
	task.Period = strings.TrimSpace(task.Period)
	task.Format = strings.TrimSpace(task.Format)
	if task.Type == "" {
		task.Type = "cleanup"
	}
	if task.ID == "" {
		task.ID = task.Type + "-" + strings.ReplaceAll(task.Target, string(filepath.Separator), "-")
	}
	if task.Name == "" {
		task.Name = task.ID
	}
	if task.Type == "backup" && (task.Name == task.ID || strings.EqualFold(task.Name, "Config backup")) {
		task.Name = "Config snapshot"
	}
	if task.Keep <= 0 {
		task.Keep = 7
	}
	if task.Frequency == "" {
		if task.Schedule != "" {
			task.Frequency = task.Schedule
		} else if task.Type == "security_report" || task.Type == "ai_self_learning" || task.Type == "self_learning_rules" {
			task.Frequency = "daily"
		} else {
			task.Frequency = "interval"
		}
	}
	if task.Frequency == "daily" || task.Frequency == "weekly" || task.Frequency == "monthly" {
		if task.At == "" {
			task.At = "08:00"
		}
	}
	if task.Frequency == "interval" && task.Every <= 0 {
		task.Every = 24 * time.Hour
	}
	if task.Type == "security_report" {
		if task.Channel == "" {
			task.Channel = "file"
		}
		if task.Recipient == "" {
			task.Recipient = "./data/reports"
		}
		if task.Period == "" {
			task.Period = "daily"
		}
		if task.Format == "" {
			task.Format = "markdown"
		}
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now().UTC()
	}
}

func (h *Handler) normalizedTaskConfigs() []config.ScheduledTaskConfig {
	if h == nil || h.Config == nil {
		return nil
	}
	tasks := make([]config.ScheduledTaskConfig, len(h.Config.Scheduler.Tasks))
	copy(tasks, h.Config.Scheduler.Tasks)
	for index := range tasks {
		normalizeScheduledTask(&tasks[index])
	}
	return tasks
}

func scheduledTaskResponses(tasks []config.ScheduledTaskConfig) []scheduledTaskResponse {
	out := make([]scheduledTaskResponse, 0, len(tasks))
	for _, task := range tasks {
		normalizeScheduledTask(&task)
		out = append(out, scheduledTaskResponse{
			ID:        task.ID,
			Name:      task.Name,
			Type:      task.Type,
			Schedule:  task.Schedule,
			Every:     durationForJSON(task.Every),
			Frequency: task.Frequency,
			At:        task.At,
			Target:    task.Target,
			Channel:   task.Channel,
			Recipient: task.Recipient,
			Period:    task.Period,
			Format:    task.Format,
			Keep:      task.Keep,
			Enabled:   task.Enabled,
			CreatedAt: task.CreatedAt,
		})
	}
	return out
}

func durationForJSON(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	if value%(24*time.Hour) == 0 {
		return formatDurationUnit(value/(24*time.Hour), "d")
	}
	if value%time.Hour == 0 {
		return formatDurationUnit(value/time.Hour, "h")
	}
	if value%time.Minute == 0 {
		return formatDurationUnit(value/time.Minute, "m")
	}
	if value%time.Second == 0 {
		return formatDurationUnit(value/time.Second, "s")
	}
	return value.String()
}

func formatDurationUnit(value time.Duration, unit string) string {
	return strconv.FormatInt(int64(value), 10) + unit
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
	writeError(w, http.StatusNotImplemented, "BACKUP_EXPORT_NOT_IMPLEMENTED", "a verified restorable backup format is not available in this version")
}

func (h *Handler) RestoreBackup(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	writeError(w, http.StatusNotImplemented, "BACKUP_RESTORE_NOT_IMPLEMENTED", "backup restore is disabled until atomic validation and rollback are available")
}

func (h *Handler) BlockPageTemplates(w http.ResponseWriter, _ *http.Request) {
	writeData(w, blockpage.TemplateLibrary())
}

func (h *Handler) BlockPageConfig(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.BlockPage)
}

func (h *Handler) PreviewBlockPageConfig(w http.ResponseWriter, r *http.Request) {
	var req config.BlockPageConfig
	if !decode(w, r, &req) {
		return
	}
	if req.TemplateID == "" {
		req.TemplateID = h.Config.BlockPage.TemplateID
		if req.TemplateID == "" {
			req.TemplateID = config.Default().BlockPage.TemplateID
		}
	}
	if strings.TrimSpace(req.CustomHTML) == "" {
		req.CustomEnabled = false
	}
	renderer, err := blockpage.NewRendererFromConfig(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_TEMPLATE_INVALID", err.Error())
		return
	}
	eventID := blockpage.NewTraceID()
	html, data := renderer.RenderHTML(http.StatusForbidden, blockpage.Data{
		EventID:    eventID,
		TraceID:    eventID,
		AttackType: "preview",
		ClientIP:   clientAddressForPreview(r.RemoteAddr),
		Message:    "CheeseWAF rendered this response with the same runtime template engine used for blocked requests.",
		Timestamp:  time.Now().UTC(),
	})
	writeData(w, map[string]any{
		"html":     html,
		"event_id": data.EventID,
		"trace_id": data.TraceID,
		"status":   data.Status,
	})
}

func (h *Handler) UpdateBlockPageConfig(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.BlockPageConfig
	if !decode(w, r, &req) {
		return
	}
	if req.TemplateID == "" {
		req.TemplateID = h.Config.BlockPage.TemplateID
		if req.TemplateID == "" {
			req.TemplateID = config.Default().BlockPage.TemplateID
		}
	}
	if strings.TrimSpace(req.CustomHTML) == "" {
		req.CustomEnabled = false
	}
	if !h.applyBlockPageConfig(w, req) {
		return
	}
	writeData(w, h.Config.BlockPage)
}

func (h *Handler) UploadBlockPageHTML(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(config.MaxBlockPageHTMLBytes+4096))
	if err := r.ParseMultipartForm(int64(config.MaxBlockPageHTMLBytes + 4096)); err != nil {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_UPLOAD_INVALID", err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_UPLOAD_MISSING", "html file field is required")
		return
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, int64(config.MaxBlockPageHTMLBytes+1)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_UPLOAD_READ_ERROR", err.Error())
		return
	}
	if len(body) > config.MaxBlockPageHTMLBytes {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_UPLOAD_TOO_LARGE", "custom block page HTML exceeds maximum size")
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_UPLOAD_EMPTY", "custom block page HTML is empty")
		return
	}
	if !validBlockPageHTMLUpload(header.Filename, body) {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_UPLOAD_NOT_HTML", "upload a .html or .htm file containing an HTML document or fragment")
		return
	}
	next := h.Config.BlockPage
	if templateID := strings.TrimSpace(r.FormValue("template_id")); templateID != "" {
		next.TemplateID = templateID
	}
	if next.TemplateID == "" {
		next.TemplateID = config.Default().BlockPage.TemplateID
	}
	next.CustomEnabled = true
	next.CustomHTML = string(body)
	if !h.applyBlockPageConfig(w, next) {
		return
	}
	writeData(w, map[string]any{"config": h.Config.BlockPage, "filename": header.Filename, "bytes": len(body)})
}

func validBlockPageHTMLUpload(filename string, body []byte) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".html" && ext != ".htm" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	for _, marker := range []string{"<!doctype html", "<html", "<body", "<main", "<section", "<div"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func clientAddressForPreview(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
		return host
	}
	if strings.TrimSpace(remoteAddr) != "" {
		return remoteAddr
	}
	return "console-preview"
}

func (h *Handler) DeleteCustomBlockPage(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	next := h.Config.BlockPage
	next.CustomEnabled = false
	next.CustomHTML = ""
	if next.TemplateID == "" {
		next.TemplateID = config.Default().BlockPage.TemplateID
	}
	if !h.applyBlockPageConfig(w, next) {
		return
	}
	writeData(w, h.Config.BlockPage)
}

func (h *Handler) applyBlockPageConfig(w http.ResponseWriter, next config.BlockPageConfig) bool {
	if _, ok := blockpage.TemplateByID(next.TemplateID); !ok {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_TEMPLATE_UNKNOWN", "unknown block page template")
		return false
	}
	if _, err := blockpage.NewRendererFromConfig(next); err != nil {
		writeError(w, http.StatusBadRequest, "BLOCK_PAGE_TEMPLATE_INVALID", err.Error())
		return false
	}
	_, err := h.commitConfigMutation(func(candidate *config.Config) error {
		candidate.BlockPage = next
		return nil
	}, func(candidate *config.Config) error {
		return h.notifyBlockPageConfigChanged(candidate.BlockPage)
	})
	if err != nil {
		code := "BLOCK_PAGE_SAVE_ERROR"
		if strings.Contains(err.Error(), "apply runtime config:") {
			code = "BLOCK_PAGE_RELOAD_ERROR"
		}
		writeError(w, http.StatusInternalServerError, code, err.Error())
		return false
	}
	return true
}

func (h *Handler) ImportNginx(w http.ResponseWriter, r *http.Request) {
	const maxNginxImportBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxNginxImportBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if len(body) > maxNginxImportBytes {
		writeError(w, http.StatusBadRequest, "NGINX_IMPORT_TOO_LARGE", "nginx configuration exceeds maximum import size")
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
