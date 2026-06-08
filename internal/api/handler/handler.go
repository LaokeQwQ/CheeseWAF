package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Tokens              *middleware.TokenManager
	Auditor             *middleware.Auditor
	StartedAt           time.Time
	OnSitesChanged      func([]config.SiteConfig)
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
}

type Options struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Tokens              *middleware.TokenManager
	Auditor             *middleware.Auditor
	OnSitesChanged      func([]config.SiteConfig)
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
}

func New(opts Options) *Handler {
	return &Handler{
		Config:              opts.Config,
		ConfigPath:          opts.ConfigPath,
		Store:               opts.Store,
		Sink:                opts.Sink,
		Tokens:              opts.Tokens,
		Auditor:             opts.Auditor,
		StartedAt:           time.Now().UTC(),
		OnSitesChanged:      opts.OnSitesChanged,
		OnProtectionChanged: opts.OnProtectionChanged,
		OnAPISecChanged:     opts.OnAPISecChanged,
	}
}

func (h *Handler) notifyProtectionChanged() error {
	if h == nil || h.OnProtectionChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnProtectionChanged(h.Config.Protection)
}

func (h *Handler) notifyAPISecChanged() error {
	if h == nil || h.OnAPISecChanged == nil || h.Config == nil {
		return nil
	}
	return h.OnAPISecChanged(h.Config.APISec)
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{"status": "ok", "uptime_seconds": int(time.Since(h.StartedAt).Seconds())})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if !decode(w, r, &req) {
		return
	}
	h.pruneExpiredSessions(r)
	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	if user.TwoFAEnabled {
		if req.TOTPCode == "" {
			writeError(w, http.StatusUnauthorized, "TWO_FA_REQUIRED", "two-factor code required")
			return
		}
		if !verifyTOTP(user.TwoFASecret, req.TOTPCode, time.Now().UTC()) {
			writeError(w, http.StatusUnauthorized, "INVALID_TWO_FA_CODE", "invalid two-factor code")
			return
		}
	}
	token, claims, err := h.Tokens.SignWithClaims(user.ID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	if err := h.Store.CreateSession(r.Context(), sessionFromClaims(claims)); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"token": token, "user": user})
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	user, err := h.Store.GetUserByUsername(r.Context(), claims.Username)
	if err != nil || user == nil || user.ID != claims.Subject {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	token, nextClaims, err := h.Tokens.SignWithClaims(user.ID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	if err := h.Store.RotateSession(r.Context(), claims.ID, user.ID, sessionFromClaims(nextClaims)); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"token": token, "user": user})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	if err := h.Store.RevokeSession(r.Context(), claims.ID, claims.Subject); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"revoked": true})
}

func (h *Handler) revokeUserSessions(w http.ResponseWriter, r *http.Request, userID string, exceptID string) bool {
	if err := h.Store.RevokeUserSessions(r.Context(), userID, exceptID); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_ERROR", err.Error())
		return false
	}
	return true
}

func (h *Handler) pruneExpiredSessions(r *http.Request) {
	if h == nil || h.Store == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	_, _ = h.Store.PruneSessions(r.Context(), cutoff)
}

func sessionFromClaims(claims *middleware.Claims) *storage.Session {
	if claims == nil {
		return nil
	}
	return &storage.Session{
		ID:        claims.ID,
		UserID:    claims.Subject,
		Username:  claims.Username,
		Role:      claims.Role,
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.Expires, 0).UTC(),
	}
}

func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	var req dto.SetupRequest
	if !decode(w, r, &req) {
		return
	}
	defaultAdminListen := setup.DefaultAdminListen
	if h.Config != nil && h.Config.Server.AdminListen != "" {
		defaultAdminListen = h.Config.Server.AdminListen
	}
	result, err := setup.CompleteSetup(r.Context(), setup.CompleteOptions{
		Config:             h.Config,
		ConfigPath:         h.ConfigPath,
		Store:              h.Store,
		DefaultAdminListen: defaultAdminListen,
	}, setup.SetupPayload{
		Username:      req.Username,
		Password:      req.Password,
		AdminListen:   req.AdminListen,
		AdminStrategy: req.AdminStrategy,
		AdminPublic:   req.AdminPublic,
	})
	if err != nil {
		status := setup.SetupErrorStatus(err)
		code := "SETUP_ERROR"
		if status == http.StatusBadRequest {
			code = "SETUP_VALIDATION"
		}
		if status == http.StatusConflict {
			code = "SETUP_COMPLETE"
		}
		writeError(w, status, code, err.Error())
		return
	}
	if result.Config != nil {
		h.Config = result.Config
	}
	writeData(w, map[string]any{"user": result.User, "setup_complete": true})
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	if err := json.NewDecoder(r.Body).Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return false
	}
	return true
}

func writeData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dto.Response{Data: data})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dto.Response{Error: &dto.APIError{Code: code, Message: message}})
}
