package handler

import (
	"net/http"
	"runtime"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

func (h *Handler) Stats(w http.ResponseWriter, _ *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	writeData(w, map[string]any{
		"uptime_seconds": int(time.Since(h.StartedAt).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"process_count":  monitor.CollectProcessCount(),
		"memory_alloc":   mem.Alloc,
		"sites":          len(h.Config.Sites),
		"status":         "running",
	})
}
