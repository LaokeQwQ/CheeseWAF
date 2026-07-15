package handler

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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

type twoFAPayload struct {
	Secret   string `json:"secret"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

type twoFARecoveryPayload struct {
	Password        string `json:"password"`
	ConfirmUsername string `json:"confirm_username"`
}

type twoFAState struct {
	mu      sync.Mutex
	pending map[string]twoFAPendingSecret
}

type twoFAPendingSecret struct {
	Secret    string
	ExpiresAt time.Time
	Attempts  int
}

const (
	twoFAPendingSecretTTL         = 10 * time.Minute
	twoFAPendingSecretMaxAttempts = 5
)

func newTwoFAState() *twoFAState {
	return &twoFAState{pending: map[string]twoFAPendingSecret{}}
}

func (h *Handler) twoFATracker() *twoFAState {
	if h.TwoFAState == nil {
		h.TwoFAState = newTwoFAState()
	}
	return h.TwoFAState
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
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
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
	if err := h.validateUserRole(req.Role); err != nil {
		writeError(w, http.StatusBadRequest, "ROLE_INVALID", err.Error())
		return
	}
	if err := h.validateRoleGrant(r, req.Role); err != nil {
		writeError(w, http.StatusForbidden, "ROLE_CHANGE_FORBIDDEN", err.Error())
		return
	}
	user := &storage.User{ID: uuid.NewString(), Username: req.Username, PasswordHash: string(hash), Role: req.Role}
	if err := h.Store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, user)
}

func (h *Handler) SetupUser2FA(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userByID(w, r)
	if !ok {
		return
	}
	if !h.authorizeUser2FA(w, r, user) {
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TWO_FA_ERROR", err.Error())
		return
	}
	now := h.nowUTC()
	h.twoFATracker().storePending(user.ID, secret, now.Add(twoFAPendingSecretTTL), now)
	writeData(w, map[string]string{
		"secret":      secret,
		"otpauth_url": totpURL(user.Username, secret),
	})
}

func (h *Handler) EnableUser2FA(w http.ResponseWriter, r *http.Request) {
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	user, ok := h.userByID(w, r)
	if !ok {
		return
	}
	if !h.authorizeUser2FA(w, r, user) {
		return
	}
	var req twoFAPayload
	if !decode(w, r, &req) {
		return
	}
	if req.Secret == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "secret and code are required")
		return
	}
	now := h.nowUTC()
	switch h.twoFATracker().verifyAndConsumePending(user.ID, req.Secret, req.Code, now) {
	case twoFAPendingInvalidCode:
		writeError(w, http.StatusBadRequest, "INVALID_TWO_FA_CODE", "invalid two-factor code")
		return
	case twoFAPendingUnavailable:
		writeError(w, http.StatusBadRequest, "TWO_FA_SECRET_INVALID", "two-factor secret is not pending for this user")
		return
	}
	user.TwoFAEnabled = true
	user.TwoFASecret = req.Secret
	if err := h.Store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if !h.revokeUserSessions(w, r, user.ID, "") {
		return
	}
	writeData(w, user)
}

func (h *Handler) DisableUser2FA(w http.ResponseWriter, r *http.Request) {
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
	user, ok := h.userByID(w, r)
	if !ok {
		return
	}
	if !h.authorizeUser2FA(w, r, user) {
		return
	}
	if user.TwoFAEnabled {
		var req twoFAPayload
		if !decode(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.Password) == "" || strings.TrimSpace(req.Code) == "" {
			writeError(w, http.StatusUnauthorized, "TWO_FA_REQUIRED", "current password and two-factor code are required")
			return
		}
		if !h.verifyCurrentCallerPassword(r, req.Password) {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid current password or two-factor code")
			return
		}
		if !verifyTOTP(user.TwoFASecret, req.Code, h.nowUTC()) {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid current password or two-factor code")
			return
		}
	}
	user.TwoFAEnabled = false
	user.TwoFASecret = ""
	if err := h.Store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	if !h.revokeUserSessions(w, r, user.ID, "") {
		return
	}
	writeData(w, user)
}

func (h *Handler) RecoverUser2FA(w http.ResponseWriter, r *http.Request) {
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()

	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}
	if claims.Role == "api_token" || claims.Role != "admin" || claims.Subject == "" || claims.ID == "" {
		writeError(w, http.StatusForbidden, "TWO_FA_RECOVERY_FORBIDDEN", "two-factor recovery requires an administrator user session")
		return
	}

	user, ok := h.userByID(w, r)
	if !ok {
		return
	}
	if user.ID == claims.Subject {
		writeError(w, http.StatusForbidden, "TWO_FA_RECOVERY_FORBIDDEN", "use the account-owner two-factor disable flow")
		return
	}

	var req twoFARecoveryPayload
	if !decode(w, r, &req) {
		return
	}
	if !h.verifyCurrentCallerPassword(r, req.Password) || strings.TrimSpace(req.ConfirmUsername) != user.Username {
		writeError(w, http.StatusUnauthorized, "INVALID_RECOVERY_CONFIRMATION", "invalid recovery confirmation")
		return
	}

	user.TwoFAEnabled = false
	user.TwoFASecret = ""
	if err := h.Store.UpdateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	h.twoFATracker().clearPending(user.ID)
	if !h.revokeUserSessions(w, r, user.ID, "") {
		return
	}
	writeData(w, user)
}

func (h *Handler) verifyCurrentCallerPassword(r *http.Request, password string) bool {
	if h == nil || h.Store == nil || r == nil || strings.TrimSpace(password) == "" {
		return false
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || claims.Subject == "" || claims.Username == "" {
		return false
	}
	caller, err := h.Store.GetUserByUsername(r.Context(), claims.Username)
	if err != nil || caller == nil || caller.ID != claims.Subject {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(caller.PasswordHash), []byte(password)) == nil
}

func (h *Handler) userByID(w http.ResponseWriter, r *http.Request) (*storage.User, bool) {
	id := chi.URLParam(r, "id")
	users, err := h.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return nil, false
	}
	for idx := range users {
		if users[idx].ID == id {
			copy := users[idx]
			return &copy, true
		}
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
	return nil, false
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	h.userMutationMu.Lock()
	defer h.userMutationMu.Unlock()
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
	if user.Role == "admin" && !callerIsAdmin(r) {
		writeError(w, http.StatusForbidden, "USER_UPDATE_FORBIDDEN", "only an admin can modify an admin user")
		return
	}
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Role != "" {
		if err := h.validateUserRole(req.Role); err != nil {
			writeError(w, http.StatusBadRequest, "ROLE_INVALID", err.Error())
			return
		}
		if err := h.validateUserRoleChange(r, users, user, req.Role); err != nil {
			writeError(w, http.StatusForbidden, "ROLE_CHANGE_FORBIDDEN", err.Error())
			return
		}
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
	if !h.revokeUserSessions(w, r, user.ID, "") {
		return
	}
	writeData(w, user)
}

func (h *Handler) validateUserRole(role string) error {
	role = strings.TrimSpace(role)
	if role == "" {
		return fmt.Errorf("role is required")
	}
	if strings.Contains(role, "*") || strings.Contains(role, ":") || strings.ContainsAny(role, " \t\r\n") {
		return fmt.Errorf("role must be a configured role name, not a permission expression")
	}
	permissions := config.Default().APISec.Permissions
	if h != nil && h.Config != nil && len(h.Config.APISec.Permissions) > 0 {
		permissions = h.Config.APISec.Permissions
	}
	if _, ok := permissions[role]; ok {
		return nil
	}
	return fmt.Errorf("unknown role %q", role)
}

func (h *Handler) validateUserRoleChange(r *http.Request, users []storage.User, user *storage.User, nextRole string) error {
	if user == nil {
		return fmt.Errorf("user is required")
	}
	nextRole = strings.TrimSpace(nextRole)
	if nextRole != user.Role {
		if err := h.validateRoleGrant(r, nextRole); err != nil {
			return err
		}
	}
	if user.Role == "admin" && nextRole != "admin" && countAdminUsers(users) <= 1 {
		return fmt.Errorf("cannot remove the last admin")
	}
	return nil
}

func (h *Handler) validateRoleGrant(r *http.Request, role string) error {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		return fmt.Errorf("caller is not authenticated")
	}
	if claims.Role == "admin" {
		return nil
	}
	for _, permission := range h.rolePermissions(role) {
		if !h.callerHasPermission(claims, permission) {
			return fmt.Errorf("role %q exceeds caller permissions", role)
		}
	}
	return nil
}

func (h *Handler) rolePermissions(role string) []string {
	permissions := config.Default().APISec.Permissions
	if h != nil && h.Config != nil && len(h.Config.APISec.Permissions) > 0 {
		permissions = h.Config.APISec.Permissions
	}
	return append([]string(nil), permissions[strings.TrimSpace(role)]...)
}

func callerIsAdmin(r *http.Request) bool {
	if r == nil {
		return false
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	return claims != nil && claims.Role == "admin"
}

func countAdminUsers(users []storage.User) int {
	count := 0
	for _, user := range users {
		if user.Role == "admin" {
			count++
		}
	}
	return count
}

func (s *twoFAState) storePending(userID, secret string, expiresAt, now time.Time) {
	if s == nil || userID == "" || secret == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.pending[userID] = twoFAPendingSecret{Secret: secret, ExpiresAt: expiresAt}
}

func (s *twoFAState) clearPending(userID string) {
	if s == nil || userID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, userID)
}

type twoFAPendingResult int

const (
	twoFAPendingUnavailable twoFAPendingResult = iota
	twoFAPendingInvalidCode
	twoFAPendingConsumed
)

func (s *twoFAState) verifyAndConsumePending(userID, secret, code string, now time.Time) twoFAPendingResult {
	if s == nil || userID == "" || secret == "" {
		return twoFAPendingUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	pending, ok := s.pending[userID]
	if !ok || pending.Secret != secret || !pending.ExpiresAt.After(now) {
		return twoFAPendingUnavailable
	}
	if !verifyTOTP(secret, code, now) {
		pending.Attempts++
		if pending.Attempts >= twoFAPendingSecretMaxAttempts {
			delete(s.pending, userID)
		} else {
			s.pending[userID] = pending
		}
		return twoFAPendingInvalidCode
	}
	delete(s.pending, userID)
	return twoFAPendingConsumed
}

func (h *Handler) authorizeUser2FA(w http.ResponseWriter, r *http.Request, user *storage.User) bool {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return false
	}
	if claims.Role == "api_token" {
		writeError(w, http.StatusForbidden, "TWO_FA_ENROLLMENT_REQUIRES_USER", "two-factor enrollment requires an authenticated user session")
		return false
	}
	if claims.Subject == user.ID {
		return true
	}
	writeError(w, http.StatusForbidden, "USER_UPDATE_FORBIDDEN", "two-factor authentication can only be changed by the account owner")
	return false
}

func (h *Handler) callerHasPermission(claims *middleware.Claims, required string) bool {
	if claims == nil {
		return false
	}
	configured := config.Default().APISec.Permissions
	if h != nil && h.Config != nil && len(h.Config.APISec.Permissions) > 0 {
		configured = h.Config.APISec.Permissions
	}
	for _, permission := range append(append([]string(nil), claims.Scopes...), configured[claims.Role]...) {
		if permission == "*" || permission == required || (strings.HasSuffix(permission, "*") && strings.HasPrefix(required, strings.TrimSuffix(permission, "*"))) {
			return true
		}
	}
	return false
}

func (s *twoFAState) pruneLocked(now time.Time) {
	for userID, pending := range s.pending {
		if !pending.ExpiresAt.After(now) {
			delete(s.pending, userID)
		}
	}
}
