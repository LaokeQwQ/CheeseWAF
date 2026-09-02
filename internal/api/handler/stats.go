package handler

import (
	"net/http"
	"runtime"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

func (h *Handler) Stats(w http.ResponseWriter, _ *http.Request) {
	memoryAlloc := h.cachedMemoryAlloc(h.nowUTC())
	writeData(w, map[string]any{
		"uptime_seconds": int(time.Since(h.StartedAt).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"process_count":  monitor.CollectProcessCount(),
		"memory_alloc":   memoryAlloc,
		"sites":          len(h.currentConfig().Sites),
		"status":         "running",
	})
}

func (h *Handler) cachedMemoryAlloc(now time.Time) uint64 {
	h.memoryStatsMu.Lock()
	defer h.memoryStatsMu.Unlock()
	if !h.memoryStatsAt.IsZero() && now.Sub(h.memoryStatsAt) < 5*time.Second {
		return h.memoryAlloc
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	h.memoryAlloc = mem.Alloc
	h.memoryStatsAt = now
	return h.memoryAlloc
}
