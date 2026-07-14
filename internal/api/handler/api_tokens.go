package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var (
	errManagementAPITokenConfigInvalid = errors.New("management api token config is invalid")
	errManagementAPITokenNotFound      = errors.New("management api token not found")
)

type managementAPITokenPayload struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	TTL       string   `json:"ttl"`
	ExpiresAt string   `json:"expires_at"`
	Notes     string   `json:"notes"`
	Enabled   *bool    `json:"enabled"`
}

type managementAPITokenView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"prefix"`
	Scopes     []string  `json:"scopes"`
	Notes      string    `json:"notes,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

func (h *Handler) ListManagementAPITokens(w http.ResponseWriter, _ *http.Request) {
	h.configMutationMu.RLock()
	defer h.configMutationMu.RUnlock()
	items := managementAPITokenViews(h.Config.APISec.ManagementAPI.Tokens)
	writeData(w, map[string]any{"enabled": h.Config.APISec.ManagementAPI.Enabled, "items": items, "total": len(items)})
}

func (h *Handler) AuthenticateManagementAPIToken(raw string, at time.Time) (*middleware.Claims, func(), bool) {
	if h == nil || h.Config == nil {
		return nil, nil, false
	}
	h.configMutationMu.Lock()
	claims, ok := middleware.VerifyManagementAPIToken(raw, h.Config.APISec.ManagementAPI, at)
	if !ok {
		h.configMutationMu.Unlock()
		return nil, nil, false
	}
	for idx := range h.Config.APISec.ManagementAPI.Tokens {
		token := &h.Config.APISec.ManagementAPI.Tokens[idx]
		if token.ID != claims.ID {
			continue
		}
		interval := h.managementTokenFlushInterval
		if interval <= 0 {
			interval = time.Minute
		}
		if !token.LastUsedAt.IsZero() && at.Sub(token.LastUsedAt) < interval {
			h.configMutationMu.Unlock()
			h.configMutationMu.RLock()
			claims, ok = middleware.VerifyManagementAPIToken(raw, h.Config.APISec.ManagementAPI, at)
			if !ok {
				h.configMutationMu.RUnlock()
				return nil, nil, false
			}
			return claims, h.configMutationMu.RUnlock, true
		}
		previous := token.LastUsedAt
		token.LastUsedAt = at.UTC()
		if err := h.persistManagementAPITokenUseLocked(); err != nil {
			token.LastUsedAt = previous
		}
		h.configMutationMu.Unlock()
		h.configMutationMu.RLock()
		claims, ok = middleware.VerifyManagementAPIToken(raw, h.Config.APISec.ManagementAPI, at)
		if !ok {
			h.configMutationMu.RUnlock()
			return nil, nil, false
		}
		return claims, h.configMutationMu.RUnlock, true
	}
	h.configMutationMu.Unlock()
	return nil, nil, false
}

func (h *Handler) persistManagementAPITokenUseLocked() error {
	if h == nil || h.Config == nil || h.ConfigPath == "" {
		return nil
	}
	return config.Save(h.ConfigPath, h.Config)
}

func (h *Handler) CreateManagementAPIToken(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	if h.Config == nil || !h.Config.APISec.ManagementAPI.Enabled {
		writeError(w, http.StatusBadRequest, "API_TOKEN_DISABLED", "management api tokens are disabled")
		return
	}
	var req managementAPITokenPayload
	if !decode(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token name is required")
		return
	}
	scopes := normalizeScopes(req.Scopes)
	if len(scopes) == 0 {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "at least one scope is required")
		return
	}
	if err := h.validateManagementAPITokenScopes(r, scopes); err != nil {
		writeError(w, http.StatusForbidden, "API_TOKEN_SCOPE_FORBIDDEN", err.Error())
		return
	}
	now := time.Now().UTC()
	expiresAt, ok := parseManagementAPITokenExpiry(w, req, now)
	if !ok {
		return
	}
	raw, err := newManagementAPITokenSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "API_TOKEN_GENERATE_FAILED", err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	item := config.ManagementAPITokenConfig{
		ID:        uuid.NewString(),
		Name:      name,
		Prefix:    managementAPITokenDisplayPrefix(raw),
		Hash:      middleware.HashManagementAPIToken(raw),
		Scopes:    scopes,
		Notes:     strings.TrimSpace(req.Notes),
		Enabled:   enabled,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: expiresAt,
	}

	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		candidate.APISec.ManagementAPI.Tokens = append(candidate.APISec.ManagementAPI.Tokens, item)
		if err := config.Validate(candidate); err != nil {
			return fmt.Errorf("%w: %v", errManagementAPITokenConfigInvalid, err)
		}
		return nil
	}, nil)
	if err != nil {
		if errors.Is(err, errManagementAPITokenConfigInvalid) {
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	created := committed.APISec.ManagementAPI.Tokens[len(committed.APISec.ManagementAPI.Tokens)-1]
	writeData(w, map[string]any{"token": raw, "item": managementAPITokenViewFromConfig(created)})
}

func (h *Handler) RevokeManagementAPIToken(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token id is required")
		return
	}
	now := time.Now().UTC()
	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		for idx := range candidate.APISec.ManagementAPI.Tokens {
			if candidate.APISec.ManagementAPI.Tokens[idx].ID != id {
				continue
			}
			candidate.APISec.ManagementAPI.Tokens[idx].Enabled = false
			candidate.APISec.ManagementAPI.Tokens[idx].RevokedAt = now
			candidate.APISec.ManagementAPI.Tokens[idx].UpdatedAt = now
			if err := config.Validate(candidate); err != nil {
				return fmt.Errorf("%w: %v", errManagementAPITokenConfigInvalid, err)
			}
			return nil
		}
		return errManagementAPITokenNotFound
	}, nil)
	if err != nil {
		if errors.Is(err, errManagementAPITokenNotFound) {
			writeError(w, http.StatusNotFound, "API_TOKEN_NOT_FOUND", "api token not found")
			return
		}
		if errors.Is(err, errManagementAPITokenConfigInvalid) {
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	var revoked config.ManagementAPITokenConfig
	for _, token := range committed.APISec.ManagementAPI.Tokens {
		if token.ID == id {
			revoked = token
			break
		}
	}
	writeData(w, map[string]any{"revoked": true, "item": managementAPITokenViewFromConfig(revoked)})
}

func parseManagementAPITokenExpiry(w http.ResponseWriter, req managementAPITokenPayload, now time.Time) (time.Time, bool) {
	if strings.TrimSpace(req.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "expires_at must be RFC3339 time")
			return time.Time{}, false
		}
		return expiresAt.UTC(), true
	}
	if strings.TrimSpace(req.TTL) == "" {
		return time.Time{}, true
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(req.TTL))
	if err != nil {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "ttl must be a duration such as 1h or 720h")
		return time.Time{}, false
	}
	if ttl <= 0 || ttl > 366*24*time.Hour {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "ttl must be between 1s and 366d")
		return time.Time{}, false
	}
	return now.Add(ttl), true
}

func normalizeScopes(scopes []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func (h *Handler) validateManagementAPITokenScopes(r *http.Request, scopes []string) error {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		return fmt.Errorf("caller is not authenticated")
	}
	permissions := config.Default().APISec.Permissions
	if h != nil && h.Config != nil && len(h.Config.APISec.Permissions) > 0 {
		permissions = h.Config.APISec.Permissions
	}
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "*" {
			if claims.Role == "admin" {
				continue
			}
			return fmt.Errorf("wildcard * scope can only be granted by an admin")
		}
		if !callerHasPermission(claims, permissions, scope) {
			return fmt.Errorf("scope %q exceeds caller permissions", scope)
		}
	}
	return nil
}

func callerHasPermission(claims *middleware.Claims, permissions map[string][]string, required string) bool {
	if claims == nil {
		return false
	}
	if claims.Role == "admin" {
		return true
	}
	for _, scope := range claims.Scopes {
		if permissionMatches(scope, required) {
			return true
		}
	}
	for _, permission := range permissions[claims.Role] {
		if permissionMatches(permission, required) {
			return true
		}
	}
	return false
}

func permissionMatches(permission, required string) bool {
	permission = strings.TrimSpace(permission)
	required = strings.TrimSpace(required)
	if permission == "*" || permission == required {
		return true
	}
	if strings.HasSuffix(permission, "*") {
		return strings.HasPrefix(required, strings.TrimSuffix(permission, "*"))
	}
	return false
}

func newManagementAPITokenSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate api token: %w", err)
	}
	return middleware.ManagementAPITokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func managementAPITokenDisplayPrefix(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= 18 {
		return raw
	}
	return raw[:18]
}

func managementAPITokenViews(tokens []config.ManagementAPITokenConfig) []managementAPITokenView {
	items := make([]managementAPITokenView, 0, len(tokens))
	for _, token := range tokens {
		items = append(items, managementAPITokenViewFromConfig(token))
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items
}

func managementAPITokenViewFromConfig(token config.ManagementAPITokenConfig) managementAPITokenView {
	return managementAPITokenView{
		ID:         token.ID,
		Name:       token.Name,
		Prefix:     token.Prefix,
		Scopes:     append([]string(nil), token.Scopes...),
		Notes:      token.Notes,
		Enabled:    token.Enabled && token.RevokedAt.IsZero(),
		CreatedAt:  token.CreatedAt,
		UpdatedAt:  token.UpdatedAt,
		LastUsedAt: token.LastUsedAt,
		ExpiresAt:  token.ExpiresAt,
		RevokedAt:  token.RevokedAt,
	}
}
