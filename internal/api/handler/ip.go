package handler

import (
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func (h *Handler) ListIPRules(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"whitelist": h.Config.Protection.IP.Whitelist,
		"blacklist": h.Config.Protection.IP.Blacklist,
		"tags":      h.Config.Protection.IP.Tags,
		"geoip":     h.Config.Protection.IP.GeoIP,
	})
}

func (h *Handler) Protection(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.Protection)
}

func (h *Handler) UpdateIPRules(w http.ResponseWriter, r *http.Request) {
	var req config.IPProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.IP = req
	writeData(w, h.Config.Protection.IP)
}

func (h *Handler) UpdateACLRules(w http.ResponseWriter, r *http.Request) {
	var req config.ACLProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.ACL = req
	writeData(w, h.Config.Protection.ACL)
}

func (h *Handler) UpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	var req config.RateLimitProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.RateLimit = req
	writeData(w, h.Config.Protection.RateLimit)
}
