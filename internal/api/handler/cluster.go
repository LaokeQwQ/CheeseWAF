package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
)

func (h *Handler) ClusterStatus(w http.ResponseWriter, r *http.Request) {
	writeData(w, cluster.FromConfig(h.Config, requestLanguage(r)))
}

func (h *Handler) ClusterHealth(w http.ResponseWriter, r *http.Request) {
	status := cluster.FromConfig(h.Config, requestLanguage(r))
	code := http.StatusOK
	if status.Enabled && !status.CanReceiveTraffic {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(dto.Response{Data: status})
}

func requestLanguage(r *http.Request) string {
	if r == nil {
		return "zh-CN"
	}
	raw := r.Header.Get("Accept-Language")
	if strings.TrimSpace(raw) == "" {
		return "zh-CN"
	}
	first := strings.Split(raw, ",")[0]
	first = strings.TrimSpace(strings.Split(first, ";")[0])
	if first == "" {
		return "zh-CN"
	}
	return first
}
