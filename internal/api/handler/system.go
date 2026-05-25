package handler

import "net/http"

func (h *Handler) System(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"server":     h.Config.Server,
		"storage":    h.Config.Storage,
		"logging":    h.Config.Logging,
		"protection": h.Config.Protection,
		"setup":      h.Config.Setup,
		"scheduler":  h.Config.Scheduler,
		"edge":       h.Config.Edge,
		"ai":         aiConfigView(h.Config.AI),
	})
}
