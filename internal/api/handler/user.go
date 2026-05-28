package handler

import (
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type userPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, users)
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req userPayload
	if !decode(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "username and password are required")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSWORD_ERROR", err.Error())
		return
	}
	if req.Role == "" {
		req.Role = "readonly"
	}
	user := &storage.User{ID: uuid.NewString(), Username: req.Username, PasswordHash: string(hash), Role: req.Role}
	if err := h.Store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, user)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req userPayload
	if !decode(w, r, &req) {
		return
	}
	users, err := h.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	var user *storage.User
	for idx := range users {
		if users[idx].ID == id {
			copy := users[idx]
			user = &copy
			break
		}
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusBadRequest, "PASSWORD_ERROR", err.Error())
			return
		}
		user.PasswordHash = string(hash)
	}
	if err := h.Store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, user)
}
