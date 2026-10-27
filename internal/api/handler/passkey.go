package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	accountidentity "github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

const (
	// passkeyJSONBodyLimit bounds a finish payload. Attestation objects are a
	// few kilobytes; 128 KiB leaves room without allowing unbounded reads.
	passkeyJSONBodyLimit = 128 << 10
	// passkeyReadDeadline matches the password login body deadline.
	passkeyReadDeadline = 5 * time.Second
)

type passkeyLoginBeginRequest struct {
	Username string `json:"username"`
}

type passkeyRegisterBeginRequest struct {
	Name string `json:"name,omitempty"`
}

type passkeyFinishRequest struct {
	Username     string          `json:"username,omitempty"`
	SessionToken string          `json:"session_token"`
	Credential   json.RawMessage `json:"credential"`
	Name         string          `json:"name,omitempty"`
}

type passkeyCredentialResponse struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	Transports     []string   `json:"transports,omitempty"`
	BackupEligible bool       `json:"backup_eligible"`
}

// PasskeyOptions is public. It advertises only whether passkeys are enabled and
// the relying-party identity a browser needs before starting the ceremony.
func (h *Handler) PasskeyOptions(w http.ResponseWriter, _ *http.Request) {
	cfg := h.loginConfig().Passkey
	service := h.passkey()
	if h == nil || service == nil || !cfg.Enabled {
		writeData(w, map[string]any{"enabled": false})
		return
	}
	writeData(w, map[string]any{
		"enabled":           true,
		"rp_id":             cfg.RPID,
		"rp_display_name":   cfg.RPDisplayName,
		"user_verification": string(service.Config().UserVerification),
	})
}

func (h *Handler) passkeyService(w http.ResponseWriter) *passkey.Service {
	if h == nil {
		writeError(w, http.StatusNotFound, "PASSKEY_DISABLED", "passkey authentication is not enabled")
		return nil
	}
	service := h.passkey()
	if service == nil || !h.loginConfig().Passkey.Enabled {
		writeError(w, http.StatusNotFound, "PASSKEY_DISABLED", "passkey authentication is not enabled")
		return nil
	}
	return service
}

func (h *Handler) passkeyCredentialStore(w http.ResponseWriter) passkey.Store {
	if h == nil || h.PasskeyStore == nil || !h.loginConfig().Passkey.Enabled {
		writeError(w, http.StatusNotFound, "PASSKEY_DISABLED", "passkey authentication is not enabled")
		return nil
	}
	return h.PasskeyStore
}

func decodePasskeyJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(passkeyReadDeadline))
	defer func() { _ = http.NewResponseController(w).SetReadDeadline(time.Time{}) }()
	r.Body = http.MaxBytesReader(w, r.Body, passkeyJSONBodyLimit)
	return decode(w, r, dest)
}

func decodePasskeyOptionalJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(passkeyReadDeadline))
	defer func() { _ = http.NewResponseController(w).SetReadDeadline(time.Time{}) }()
	r.Body = http.MaxBytesReader(w, r.Body, passkeyJSONBodyLimit)
	return decodeOptional(w, r, dest, passkeyJSONBodyLimit, "invalid passkey request")
}

// PasskeyLoginBegin starts a username-first assertion ceremony. Unknown users
// and users without credentials receive the same response as a failed password
// login, and both paths consume the same failure budget.
func (h *Handler) PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	service := h.passkeyService(w)
	if service == nil {
		return
	}
	if !h.loginOriginAllowed(w, r) {
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "management store is unavailable")
		return
	}
	tracker := h.loginCAPTCHATracker()
	source := h.loginAuditIP(r)
	if !tracker.acquireLoginBody(source) {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many concurrent login requests from this source")
		return
	}
	var req passkeyLoginBeginRequest
	decoded := decodePasskeyJSON(w, r, &req)
	tracker.releaseLoginBody(source)
	if !decoded {
		return
	}
	now := h.nowUTC()
	rateLimitKeys := loginRateLimitKeys(r, req.Username, h.adminPublic())
	if !tracker.loginAttemptAllowed(rateLimitKeys, now) {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many failed login attempts")
		return
	}
	if accountidentity.ValidateUsername(req.Username) != nil {
		tracker.recordLoginFailure(rateLimitKeys, now)
		writeError(w, http.StatusBadRequest, "USERNAME_INVALID", "invalid username or password")
		return
	}
	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "management store is unavailable")
		return
	}
	if user == nil {
		tracker.recordLoginFailure(rateLimitKeys, now)
		h.auditPasskeyFailure(r, nil, "unknown_user")
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	assertion, token, err := service.BeginLogin(r.Context(), passkeyUser(user))
	if err != nil {
		if errors.Is(err, passkey.ErrNoCredentials) {
			tracker.recordLoginFailure(rateLimitKeys, now)
			h.auditPasskeyFailure(r, user, "no_credentials")
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
			return
		}
		writeError(w, http.StatusInternalServerError, "PASSKEY_ERROR", "passkey sign-in is unavailable")
		return
	}
	writeData(w, map[string]any{
		"publicKey":     assertion.Response,
		"session_token": token,
	})
}

// PasskeyLoginFinish verifies an assertion and then issues exactly the same
// session token, cookie, claims, and audit record as password login.
func (h *Handler) PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	service := h.passkeyService(w)
	if service == nil {
		return
	}
	if !h.loginOriginAllowed(w, r) {
		return
	}
	if h.Store == nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "management store is unavailable")
		return
	}
	tracker := h.loginCAPTCHATracker()
	source := h.loginAuditIP(r)
	if !tracker.acquireLoginBody(source) {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many concurrent login requests from this source")
		return
	}
	var req passkeyFinishRequest
	decoded := decodePasskeyJSON(w, r, &req)
	tracker.releaseLoginBody(source)
	if !decoded {
		return
	}
	now := h.nowUTC()
	rateLimitKeys := loginRateLimitKeys(r, req.Username, h.adminPublic())
	if !tracker.loginAttemptAllowed(rateLimitKeys, now) {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many failed login attempts")
		return
	}
	if accountidentity.ValidateUsername(req.Username) != nil {
		tracker.recordLoginFailure(rateLimitKeys, now)
		writeError(w, http.StatusBadRequest, "USERNAME_INVALID", "invalid username or password")
		return
	}
	if strings.TrimSpace(req.SessionToken) == "" || len(req.Credential) == 0 || !json.Valid(req.Credential) {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey response is incomplete")
		return
	}
	if !tracker.acquireLoginSlot() {
		writeError(w, http.StatusTooManyRequests, "LOGIN_RATE_LIMITED", "too many login attempts")
		return
	}
	defer tracker.releaseLoginSlot()

	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "management store is unavailable")
		return
	}
	if user == nil {
		tracker.recordLoginFailure(rateLimitKeys, now)
		h.auditPasskeyFailure(r, nil, "unknown_user")
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	credentialRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/api/auth/passkey/login/finish", bytes.NewReader(req.Credential))
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey response is incomplete")
		return
	}
	if _, err := service.FinishLogin(r.Context(), passkeyUser(user), req.SessionToken, credentialRequest); err != nil {
		tracker.recordLoginFailure(rateLimitKeys, now)
		h.auditPasskeyFailure(r, user, "verification_failed")
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}
	committed, invalidated := h.issueLoginSession(w, r, user, "passkey")
	if !committed {
		if invalidated {
			tracker.recordLoginFailure(rateLimitKeys, now)
		}
		h.auditPasskeyFailure(r, user, "session_rejected")
		return
	}
	tracker.clearLoginFailures(rateLimitKeys, now)
}

// PasskeyRegisterBegin starts registration for the authenticated account.
func (h *Handler) PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	service := h.passkeyService(w)
	if service == nil {
		return
	}
	user, ok := h.passkeySessionUser(w, r)
	if !ok {
		return
	}
	var req passkeyRegisterBeginRequest
	if !decodePasskeyOptionalJSON(w, r, &req) {
		return
	}
	name, ok := passkeyCredentialName(w, req.Name)
	if !ok {
		return
	}
	creation, token, err := service.BeginRegistration(r.Context(), passkeyUserWithName(user, name))
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey registration could not start")
		return
	}
	writeData(w, map[string]any{
		"publicKey":     creation.Response,
		"session_token": token,
	})
}

// PasskeyRegisterFinish verifies and stores the new credential.
func (h *Handler) PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	service := h.passkeyService(w)
	if service == nil {
		return
	}
	user, ok := h.passkeySessionUser(w, r)
	if !ok {
		return
	}
	var req passkeyFinishRequest
	if !decodePasskeyJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.SessionToken) == "" || len(req.Credential) == 0 || !json.Valid(req.Credential) {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey response is incomplete")
		return
	}
	name, ok := passkeyCredentialName(w, req.Name)
	if !ok {
		return
	}
	credentialRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/api/auth/passkey/register/finish", bytes.NewReader(req.Credential))
	if err != nil {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey response is incomplete")
		return
	}
	credential, err := service.FinishRegistration(r.Context(), passkeyUserWithName(user, name), req.SessionToken, credentialRequest)
	if err != nil {
		switch {
		case errors.Is(err, passkey.ErrCredentialExists):
			writeError(w, http.StatusConflict, "PASSKEY_CREDENTIAL_EXISTS", "this passkey is already registered")
		default:
			writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey registration failed")
		}
		return
	}
	writeData(w, map[string]any{"credential": passkeyCredentialView(credential)})
}

// PasskeyCredentials lists only the authenticated account's credentials.
func (h *Handler) PasskeyCredentials(w http.ResponseWriter, r *http.Request) {
	store := h.passkeyCredentialStore(w)
	if store == nil {
		return
	}
	user, ok := h.passkeySessionUser(w, r)
	if !ok {
		return
	}
	credentials, err := store.ListByUser(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "passkey credentials could not be listed")
		return
	}
	views := make([]passkeyCredentialResponse, 0, len(credentials))
	for _, credential := range credentials {
		views = append(views, passkeyCredentialView(credential))
	}
	writeData(w, map[string]any{"credentials": views})
}

// PasskeyCredentialDelete removes one credential owned by the authenticated
// account. Credentials belonging to other accounts are reported as missing.
func (h *Handler) PasskeyCredentialDelete(w http.ResponseWriter, r *http.Request) {
	store := h.passkeyCredentialStore(w)
	if store == nil {
		return
	}
	user, ok := h.passkeySessionUser(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "credential ID is required")
		return
	}
	credentials, err := store.ListByUser(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "passkey credentials could not be listed")
		return
	}
	owned := false
	for _, credential := range credentials {
		if credential != nil && credential.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		writeError(w, http.StatusNotFound, "PASSKEY_CREDENTIAL_NOT_FOUND", "passkey credential was not found")
		return
	}
	if err := store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, passkey.ErrNotFound) {
			writeError(w, http.StatusNotFound, "PASSKEY_CREDENTIAL_NOT_FOUND", "passkey credential was not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "passkey credential could not be deleted")
		return
	}
	writeData(w, map[string]any{"deleted": true})
}

func (h *Handler) passkeySessionUser(w http.ResponseWriter, r *http.Request) (*storage.User, bool) {
	if h == nil || h.Store == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return nil, false
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || strings.TrimSpace(claims.Username) == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return nil, false
	}
	user, err := h.Store.GetUserByUsername(r.Context(), claims.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", "management store is unavailable")
		return nil, false
	}
	if user == nil || user.ID != claims.Subject {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return nil, false
	}
	return user, true
}

func passkeyUser(user *storage.User) passkey.User {
	return passkey.User{ID: user.ID, Name: user.Username, DisplayName: user.Username}
}

func passkeyUserWithName(user *storage.User, name string) passkey.User {
	ceremonyUser := passkeyUser(user)
	ceremonyUser.CredentialName = name
	return ceremonyUser
}

func passkeyCredentialName(w http.ResponseWriter, raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return passkey.DefaultCredentialName, true
	}
	if len(name) > passkey.MaxCredentialNameLen {
		writeError(w, http.StatusBadRequest, "PASSKEY_INVALID_REQUEST", "passkey name is too long")
		return "", false
	}
	return name, true
}

func passkeyCredentialView(credential *passkey.Credential) passkeyCredentialResponse {
	if credential == nil {
		return passkeyCredentialResponse{}
	}
	view := passkeyCredentialResponse{
		ID:             credential.ID,
		Name:           credential.Name,
		Transports:     append([]string(nil), credential.Transports...),
		BackupEligible: credential.BackupEligible,
	}
	if !credential.CreatedAt.IsZero() {
		created := credential.CreatedAt
		view.CreatedAt = &created
	}
	if !credential.LastUsedAt.IsZero() {
		used := credential.LastUsedAt
		view.LastUsedAt = &used
	}
	return view
}

// auditPasskeyFailure records failed passkey sign-ins. The public login routes
// are outside the authenticated audit middleware, so the handler writes these
// entries explicitly. Credential material from the request is never logged.
func (h *Handler) auditPasskeyFailure(r *http.Request, user *storage.User, reason string) {
	if h == nil || h.Auditor == nil || r == nil {
		return
	}
	entry := middleware.AuditEntry{
		Timestamp: h.nowUTC(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Status:    http.StatusUnauthorized,
		RemoteIP:  h.loginAuditIP(r),
		Target:    "auth.passkey.login",
		Message:   "passkey login failed: " + reason,
		UserAgent: r.UserAgent(),
	}
	entry.PeerIP = socketPeerIP(r)
	entry.IPSource = "socket"
	if trustedLoginClientIP(r, entry.PeerIP, h.adminPublic()) != "" {
		entry.IPSource = "local_proxy"
	}
	if user != nil {
		entry.Subject, entry.User, entry.Role = user.ID, user.Username, user.Role
	}
	_ = h.Auditor.Write(context.WithoutCancel(r.Context()), entry)
}
