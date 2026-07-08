package handler

import (
	"crypto/rand"
	"encoding/base64"
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
	items := managementAPITokenViews(h.Config.APISec.ManagementAPI.Tokens)
	writeData(w, map[string]any{"enabled": h.Config.APISec.ManagementAPI.Enabled, "items": items, "total": len(items)})
}

func (h *Handler) CreateManagementAPIToken(w http.ResponseWriter, r *http.Request) {
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

	next := *h.Config
	next.APISec.ManagementAPI.Tokens = append(append([]config.ManagementAPITokenConfig(nil), h.Config.APISec.ManagementAPI.Tokens...), item)
	if err := config.Validate(&next); err != nil {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
		return
	}
	h.Config.APISec.ManagementAPI = next.APISec.ManagementAPI
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"token": raw, "item": managementAPITokenViewFromConfig(item)})
}

func (h *Handler) RevokeManagementAPIToken(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token id is required")
		return
	}
	now := time.Now().UTC()
	next := *h.Config
	next.APISec.ManagementAPI.Tokens = append([]config.ManagementAPITokenConfig(nil), h.Config.APISec.ManagementAPI.Tokens...)
	var revoked *config.ManagementAPITokenConfig
	for idx := range next.APISec.ManagementAPI.Tokens {
		if next.APISec.ManagementAPI.Tokens[idx].ID != id {
			continue
		}
		next.APISec.ManagementAPI.Tokens[idx].Enabled = false
		next.APISec.ManagementAPI.Tokens[idx].RevokedAt = now
		next.APISec.ManagementAPI.Tokens[idx].UpdatedAt = now
		revoked = &next.APISec.ManagementAPI.Tokens[idx]
		break
	}
	if revoked == nil {
		writeError(w, http.StatusNotFound, "API_TOKEN_NOT_FOUND", "api token not found")
		return
	}
	if err := config.Validate(&next); err != nil {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
		return
	}
	h.Config.APISec.ManagementAPI = next.APISec.ManagementAPI
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"revoked": true, "item": managementAPITokenViewFromConfig(*revoked)})
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
