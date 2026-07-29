package handler

import (
	"net/http"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
)

var (
	setupDraftOnce sync.Once
	setupDrafts    *setup.DraftStore
)

func draftStore() *setup.DraftStore {
	setupDraftOnce.Do(func() {
		setupDrafts = setup.NewDraftStore(setup.DefaultDraftTTL)
	})
	return setupDrafts
}

// SetupProbe runs the first-install performance probe (R0). Only meaningful when NeedsSetup.
func (h *Handler) SetupProbe(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Config == nil {
		writeError(w, http.StatusServiceUnavailable, "SETUP_UNAVAILABLE", "setup is unavailable")
		return
	}
	if !setup.NeedsSetup(h.setupDataDir()) {
		writeError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETE", "setup is already complete")
		return
	}
	dataDir := h.setupDataDir()
	result := setup.RunProbe(r.Context(), dataDir)
	// Bind/create draft session.
	store := draftStore()
	draft, err := store.Create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SETUP_DRAFT_ERROR", err.Error())
		return
	}
	_, _ = store.Update(draft.ID, func(d *setup.SetupDraft) {
		d.Probe = &result
		d.Profile = result.Profile
	})
	http.SetCookie(w, &http.Cookie{
		Name:     setup.SetupSessionCookie,
		Value:    draft.ID,
		Path:     "/",
		HttpOnly: true,
		// Secure must be a constant true for CodeQL go/cookie-secure-not-set.
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(setup.DefaultDraftTTL.Seconds()),
	})
	writeData(w, map[string]any{
		"probe":    result,
		"draft_id": draft.ID,
		"profiles": map[string]setup.ProfileConfig{
			"low":    setup.ProfileDefaults(setup.ProfileLow),
			"medium": setup.ProfileDefaults(setup.ProfileMedium),
			"high":   setup.ProfileDefaults(setup.ProfileHigh),
		},
	})
}

// SetupDraftGet returns the current setup draft for the session cookie.
func (h *Handler) SetupDraftGet(w http.ResponseWriter, r *http.Request) {
	id := setupSessionID(r)
	if id == "" {
		writeError(w, http.StatusUnauthorized, "SETUP_SESSION_REQUIRED", "setup session required")
		return
	}
	d, ok := draftStore().Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
		return
	}
	writeData(w, d)
}

type setupDraftPatch struct {
	Profile       string               `json:"profile"`
	Custom        *setup.ProfileConfig `json:"custom"`
	Username      string               `json:"username"`
	Password      string               `json:"password"`
	AdminListen   string               `json:"admin_listen"`
	AdminStrategy string               `json:"admin_strategy"`
	Confirmed     *bool                `json:"confirmed"`
}

// SetupDraftPatch updates multi-step wizard fields. CompleteSetup remains a separate final call.
func (h *Handler) SetupDraftPatch(w http.ResponseWriter, r *http.Request) {
	id := setupSessionID(r)
	if id == "" {
		writeError(w, http.StatusUnauthorized, "SETUP_SESSION_REQUIRED", "setup session required")
		return
	}
	var req setupDraftPatch
	if !decode(w, r, &req) {
		return
	}
	if req.Password != "" {
		if !draftStore().SetPassword(id, req.Password) {
			writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
			return
		}
	}
	d, ok := draftStore().Update(id, func(d *setup.SetupDraft) {
		if req.Profile != "" {
			d.Profile = setup.HardwareProfile(req.Profile)
		}
		if req.Custom != nil {
			d.Custom = req.Custom
			d.Profile = setup.ProfileCustom
		}
		if req.Username != "" {
			d.Username = req.Username
		}
		if req.AdminListen != "" {
			d.AdminListen = req.AdminListen
		}
		if req.AdminStrategy != "" {
			d.AdminStrategy = req.AdminStrategy
		}
		if req.Confirmed != nil {
			d.Confirmed = *req.Confirmed
		}
	})
	if !ok {
		writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
		return
	}
	writeData(w, d)
}

func setupSessionID(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(setup.SetupSessionCookie)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

func (h *Handler) setupDataDir() string {
	if h != nil && h.Config != nil && h.Config.Setup.DataDir != "" {
		return h.Config.Setup.DataDir
	}
	return setup.DefaultDataDir
}
