package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Config    *config.Config
	Store     storage.Store
	Sink      storage.LogSink
	Tokens    *middleware.TokenManager
	Auditor   *middleware.Auditor
	StartedAt time.Time
}

func New(cfg *config.Config, store storage.Store, sink storage.LogSink, tokens *middleware.TokenManager, auditor *middleware.Auditor) *Handler {
	return &Handler{Config: cfg, Store: store, Sink: sink, Tokens: tokens, Auditor: auditor, StartedAt: time.Now().UTC()}
}

func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{"status": "ok", "uptime_seconds": int(time.Since(h.StartedAt).Seconds())})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if !decode(w, r, &req) {
		return
	}
	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	token, err := h.Tokens.Sign(user.ID, user.Username, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"token": token, "user": user})
}

func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	var req dto.SetupRequest
	if !decode(w, r, &req) {
		return
	}
	users, err := h.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if len(users) > 0 {
		writeError(w, http.StatusConflict, "SETUP_COMPLETE", "setup has already completed")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSWORD_ERROR", err.Error())
		return
	}
	user := &storage.User{Username: req.Username, PasswordHash: string(hash), Role: "admin"}
	if err := h.Store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"user": user})
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
