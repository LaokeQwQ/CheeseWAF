package handler

import "net/http"

func (h *Handler) ListIPRules(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"whitelist": h.Config.Protection.IP.Whitelist,
		"blacklist": h.Config.Protection.IP.Blacklist,
		"tags":      h.Config.Protection.IP.Tags,
	})
}
