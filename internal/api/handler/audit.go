package handler

import "net/http"

func (h *Handler) AuditEntries(w http.ResponseWriter, _ *http.Request) {
	if h.Auditor == nil {
		writeData(w, []any{})
		return
	}
	entries, err := h.Auditor.Query(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "AUDIT_ERROR", err.Error())
		return
	}
	writeData(w, entries)
}
