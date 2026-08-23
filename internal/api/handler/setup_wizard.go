package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
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

func (h *Handler) setupDraftStore() *setup.DraftStore {
	if h != nil && h.SetupDrafts != nil {
		return h.SetupDrafts
	}
	return draftStore()
}

// allowSetupMutation gates first-install endpoints: setup must still be needed,
// the setup token must match, and browser mutations need a local or same Origin.
func (h *Handler) allowSetupMutation(w http.ResponseWriter, r *http.Request) bool {
	if h == nil {
		writeError(w, http.StatusServiceUnavailable, "SETUP_UNAVAILABLE", "setup is unavailable")
		return false
	}
	if !setup.NeedsSetup(h.setupDataDir()) {
		writeError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETE", "setup is already complete")
		return false
	}
	// Authoritative safety: if any admin user already exists, refuse re-init even if lock is missing.
	if h.Store != nil {
		users, err := h.Store.ListUsers(r.Context())
		if err == nil && len(users) > 0 {
			writeError(w, http.StatusConflict, "SETUP_ALREADY_COMPLETE", "administrator already exists")
			return false
		}
	}
	expected := strings.TrimSpace(h.SetupToken)
	if expected == "" {
		expected = strings.TrimSpace(os.Getenv("CHEESEWAF_SETUP_TOKEN"))
	}
	if expected == "" {
		expected = setup.GetSetupToken()
	}
	got := strings.TrimSpace(r.Header.Get("X-CheeseWAF-Setup-Token"))
	if expected == "" || got == "" {
		writeError(w, http.StatusUnauthorized, "SETUP_TOKEN_REQUIRED", "setup token is required")
		return false
	}
	if !setupTokensEqual(got, expected) {
		writeError(w, http.StatusUnauthorized, "SETUP_TOKEN_REQUIRED", "setup token is invalid")
		return false
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if !isLocalOrSameOrigin(origin, r) {
				writeError(w, http.StatusForbidden, "SETUP_ORIGIN_DENIED", "setup origin is not allowed")
				return false
			}
		}
	}
	return true
}
func setupTokensEqual(got, expected string) bool {
	gotHash := sha256.Sum256([]byte(got))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(gotHash[:], expectedHash[:]) == 1
}

func isLocalOrSameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if r != nil && r.Host != "" {
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		return strings.EqualFold(host, reqHost)
	}
	return false
}

// SetupStatus reports whether first-install is still required. Setup credentials
// are delivered only through the serve process's stdout/runtime URL file.
func (h *Handler) SetupStatus(w http.ResponseWriter, r *http.Request) {
	needs := true
	if h != nil {
		needs = setup.NeedsSetup(h.setupDataDir())
		if !needs {
			writeData(w, map[string]any{"needs_setup": false})
			return
		}
		if h.Store != nil {
			users, err := h.Store.ListUsers(context.Background())
			if err == nil && len(users) > 0 {
				writeData(w, map[string]any{"needs_setup": false})
				return
			}
		}
	}
	payload := map[string]any{"needs_setup": needs}
	writeData(w, payload)
}

// SetupProbe runs the first-install performance probe (R0). Only meaningful when NeedsSetup.
func (h *Handler) SetupProbe(w http.ResponseWriter, r *http.Request) {
	if !h.allowSetupMutation(w, r) {
		return
	}
	if h.currentConfig() == nil {
		writeError(w, http.StatusServiceUnavailable, "SETUP_UNAVAILABLE", "setup is unavailable")
		return
	}
	store := h.setupDraftStore()
	draft, cached, err := store.ReserveProbe(setupSessionID(r))
	if cached {
		h.writeSetupProbeResponse(w, r, draft, *draft.Probe)
		return
	}
	if errors.Is(err, setup.ErrDraftStoreFull) {
		writeError(w, http.StatusTooManyRequests, "SETUP_CAPACITY_REACHED", "too many active setup sessions")
		return
	}
	if errors.Is(err, setup.ErrDraftProbeInProgress) {
		writeError(w, http.StatusTooManyRequests, "SETUP_PROBE_IN_PROGRESS", "setup probe is already running")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SETUP_DRAFT_ERROR", err.Error())
		return
	}
	result := h.runSetupProbe(r.Context(), h.setupDataDir())
	draft, ok := store.CompleteProbe(draft.ID, result)
	if !ok {
		writeError(w, http.StatusConflict, "SETUP_DRAFT_EXPIRED", "setup session expired while probe was running")
		return
	}
	h.writeSetupProbeResponse(w, r, draft, result)
}

func (h *Handler) writeSetupProbeResponse(w http.ResponseWriter, r *http.Request, draft *setup.SetupDraft, result setup.ProbeResult) {
	middleware.WriteCookie(w, r, &http.Cookie{
		Name:     setup.SetupSessionCookie,
		Value:    draft.ID,
		Path:     "/",
		HttpOnly: true,
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
	d, ok := h.setupDraftStore().Get(id)
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
	if !h.allowSetupMutation(w, r) {
		return
	}
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
		if !h.setupDraftStore().SetPassword(id, req.Password) {
			writeError(w, http.StatusNotFound, "SETUP_DRAFT_NOT_FOUND", "setup draft not found or expired")
			return
		}
	}
	d, ok := h.setupDraftStore().Update(id, func(d *setup.SetupDraft) {
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
	if h != nil && h.currentConfig() != nil && h.currentConfig().Setup.DataDir != "" {
		return h.currentConfig().Setup.DataDir
	}
	return setup.DefaultDataDir
}
