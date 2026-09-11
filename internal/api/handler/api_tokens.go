package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var (
	errManagementAPITokenConfigInvalid           = errors.New("management api token config is invalid")
	errManagementAPITokenNotFound                = errors.New("management api token not found")
	errManagementAPITokenCapacity                = errors.New("management api token capacity is exhausted")
	errManagementAPITokenConfirmationRequired    = errors.New("management api token never-expire confirmation is required")
	errManagementAPITokenConfirmationReplay      = errors.New("management api token confirmation has already been used")
	errManagementAPITokenConfirmationUnavailable = errors.New("management api token non-expiring confirmation is unavailable")
	errManagementAPITokenNothingToClean          = errors.New("no management api tokens require cleanup")
)

const managementTokenConfirmationRetention = 30 * time.Minute

func (h *Handler) recordManagementTokenCreation(now time.Time) {
	if h == nil || now.IsZero() {
		return
	}
	now = now.UTC()
	h.managementTokenScheduleMu.Lock()
	defer h.managementTokenScheduleMu.Unlock()
	if h.managementTokenFirstCreation.IsZero() {
		h.managementTokenFirstCreation = now
	}
	h.managementTokenLastCreation = now
	deadline := now.Add(tokens.CleanupDelay)
	capAt := h.managementTokenFirstCreation.Add(time.Hour)
	if deadline.After(capAt) {
		deadline = capAt
	}
	h.managementTokenCleanupAt = deadline
}

// NextManagementAPITokenCleanupAt exposes the coalesced cleanup deadline to a
// service scheduler. It does not force a scan or perform any mutation.
func (h *Handler) NextManagementAPITokenCleanupAt() time.Time {
	if h == nil {
		return time.Time{}
	}
	h.managementTokenScheduleMu.Lock()
	defer h.managementTokenScheduleMu.Unlock()
	return h.managementTokenCleanupAt
}

func (h *Handler) claimManagementTokenCleanup(now time.Time) bool {
	if h == nil {
		return false
	}
	h.managementTokenScheduleMu.Lock()
	defer h.managementTokenScheduleMu.Unlock()
	if h.managementTokenCleanupRunning {
		return false
	}
	h.configMutationMu.RLock()
	cfg := h.currentConfig()
	var items []config.ManagementAPITokenConfig
	if cfg != nil {
		items = cfg.APISec.ManagementAPI.Tokens
	}
	h.configMutationMu.RUnlock()
	if len(items) == 0 {
		h.managementTokenCleanupAt = time.Time{}
		h.managementTokenFirstCreation = time.Time{}
		h.managementTokenLastCreation = time.Time{}
		return false
	}
	if h.managementTokenCleanupAt.IsZero() {
		for _, token := range items {
			created := token.CreatedAt
			if created.IsZero() {
				continue
			}
			if h.managementTokenFirstCreation.IsZero() || created.Before(h.managementTokenFirstCreation) {
				h.managementTokenFirstCreation = created
			}
			if h.managementTokenLastCreation.IsZero() || created.After(h.managementTokenLastCreation) {
				h.managementTokenLastCreation = created
			}
		}
		if h.managementTokenFirstCreation.IsZero() {
			h.managementTokenFirstCreation = now
		}
		if h.managementTokenLastCreation.IsZero() {
			h.managementTokenLastCreation = h.managementTokenFirstCreation
		}
		deadline := h.managementTokenLastCreation.Add(tokens.CleanupDelay)
		capAt := h.managementTokenFirstCreation.Add(time.Hour)
		if deadline.After(capAt) {
			deadline = capAt
		}
		if deadline.Before(now) {
			deadline = now
		}
		h.managementTokenCleanupAt = deadline
	}
	if now.Before(h.managementTokenCleanupAt) {
		return false
	}
	h.managementTokenCleanupRunning = true
	return true
}

func (h *Handler) finishManagementTokenCleanup(now time.Time) {
	if h == nil {
		return
	}
	h.managementTokenScheduleMu.Lock()
	defer h.managementTokenScheduleMu.Unlock()
	h.managementTokenCleanupRunning = false
	h.configMutationMu.RLock()
	cfg := h.currentConfig()
	remaining := cfg != nil && len(cfg.APISec.ManagementAPI.Tokens) > 0
	h.configMutationMu.RUnlock()
	if !remaining {
		h.managementTokenFirstCreation = time.Time{}
		h.managementTokenLastCreation = time.Time{}
		h.managementTokenCleanupAt = time.Time{}
		return
	}
	h.managementTokenCleanupAt = now.Add(tokens.CleanupDelay)
}

// StartManagementAPITokenCleanup starts the single coalesced worker used by
// the service process. Calling it more than once is harmless. The worker is
// intentionally independent from request goroutines and stops with ctx.
func (h *Handler) StartManagementAPITokenCleanup(ctx context.Context) {
	if h == nil || ctx == nil {
		return
	}
	h.managementTokenScheduleMu.Lock()
	if h.managementTokenCleanupStarted {
		h.managementTokenScheduleMu.Unlock()
		return
	}
	h.managementTokenCleanupStarted = true
	h.managementTokenScheduleMu.Unlock()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		cleanup := func() {
			if removed, err := h.CleanupManagementAPITokens(h.nowUTC()); err != nil {
				log.Printf("management api token cleanup failed: %v", err)
			} else if removed > 0 {
				log.Printf("management api token cleanup removed %d inactive or expired token(s)", removed)
			}
		}
		cleanup()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup()
			}
		}
	}()
}

// CleanupManagementAPITokens removes expired or inactive management tokens in
// one committed configuration mutation. It is deliberately separate from the
// request authentication path so a scheduler can call it from one worker and
// avoid a scan on every API request. The removed metadata is emitted to the
// audit stream and administrator notifications after the durable mutation;
// notification failures do not resurrect a credential.
func (h *Handler) CleanupManagementAPITokens(now time.Time) (int, error) {
	if h == nil || now.IsZero() {
		return 0, fmt.Errorf("token cleanup time is required")
	}
	now = now.UTC()
	if !h.claimManagementTokenCleanup(now) {
		return 0, nil
	}
	defer h.finishManagementTokenCleanup(now)
	removed := make([]config.ManagementAPITokenConfig, 0)
	_, err := h.commitConfigMutation(func(candidate *config.Config) error {
		kept := make([]config.ManagementAPITokenConfig, 0, len(candidate.APISec.ManagementAPI.Tokens))
		for _, token := range candidate.APISec.ManagementAPI.Tokens {
			lastActivity := token.LastUsedAt
			if lastActivity.IsZero() {
				lastActivity = token.CreatedAt
			}
			expired := !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(now)
			inactive := !lastActivity.IsZero() && now.Sub(lastActivity) >= tokens.InactivityTTL
			if !expired && !inactive {
				kept = append(kept, token)
				continue
			}
			removed = append(removed, token)
		}
		if len(removed) == 0 {
			return errManagementAPITokenNothingToClean
		}
		candidate.APISec.ManagementAPI.Tokens = kept
		return nil
	}, nil)
	if errors.Is(err, errManagementAPITokenNothingToClean) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, token := range removed {
		reason := "inactive"
		if !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(now) {
			reason = "expired"
		}
		h.auditManagementTokenAutoDestroyed(now, token, reason)
		h.notifyManagementTokenAutoDestroyed(token, reason, now)
	}
	return len(removed), nil
}

func (h *Handler) auditManagementTokenAutoDestroyed(now time.Time, token config.ManagementAPITokenConfig, reason string) {
	if h == nil || h.Auditor == nil {
		return
	}
	if err := h.Auditor.Write(context.Background(), middleware.AuditEntry{
		Timestamp: now,
		Subject:   "api-token:" + token.ID,
		User:      token.Name,
		Role:      "api_token",
		Method:    "SYSTEM",
		Path:      "/api/system/api-tokens",
		Status:    http.StatusOK,
		Target:    token.ID,
		Message:   "management API token automatically destroyed: " + reason,
	}); err != nil {
		log.Printf("management api token cleanup audit failed id=%q: %v", token.ID, err)
	}
}

func (h *Handler) notifyManagementTokenAutoDestroyed(token config.ManagementAPITokenConfig, reason string, now time.Time) {
	if h == nil || h.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	users, err := h.Store.ListUsers(ctx)
	if err != nil {
		log.Printf("management api token cleanup notification lookup failed id=%q: %v", token.ID, err)
		return
	}
	for _, user := range users {
		if user.Role != "admin" {
			continue
		}
		notification := &storage.Notification{
			UserID:    user.ID,
			Type:      "warning",
			Title:     "Management API token automatically destroyed",
			Message:   fmt.Sprintf("Token %q was automatically destroyed because it was %s.", token.Name, reason),
			Target:    "/system?tab=api-tokens",
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := h.Store.CreateNotification(ctx, notification); err != nil {
			log.Printf("management api token cleanup notification failed id=%q user=%q: %v", token.ID, user.ID, err)
		}
	}
}

type managementAPITokenPayload struct {
	Name               string    `json:"name"`
	Scopes             []string  `json:"scopes"`
	TTL                string    `json:"ttl"`
	ExpiresAt          string    `json:"expires_at"`
	Notes              string    `json:"notes"`
	Enabled            *bool     `json:"enabled"`
	NeverExpire        bool      `json:"never_expire"`
	ConfirmNeverExpire bool      `json:"confirm_never_expire"`
	ConfirmationID     string    `json:"confirmation_id"`
	WarningReadAt      time.Time `json:"warning_read_at"`
	Password           string    `json:"password"`
	TOTPCode           string    `json:"totp_code"`
	SecondConfirmation bool      `json:"second_confirmation"`
	ConfirmationPhrase string    `json:"confirmation_phrase"`
}

type managementAPITokenView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Prefix      string    `json:"prefix"`
	Scopes      []string  `json:"scopes"`
	Notes       string    `json:"notes,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
	NeverExpire bool      `json:"never_expire"`
}

func (h *Handler) ListManagementAPITokens(w http.ResponseWriter, _ *http.Request) {
	h.configMutationMu.RLock()
	defer h.configMutationMu.RUnlock()
	items := managementAPITokenViews(h.currentConfig().APISec.ManagementAPI.Tokens)
	writeData(w, map[string]any{"enabled": h.currentConfig().APISec.ManagementAPI.Enabled, "items": items, "total": len(items)})
}

func (h *Handler) AuthenticateManagementAPIToken(raw string, at time.Time) (*middleware.Claims, func(), bool) {
	if h == nil || h.currentConfig() == nil {
		return nil, nil, false
	}
	at = at.UTC()
	// Copy the small authentication snapshot while locked, then perform digest or
	// legacy bcrypt verification without holding configuration locks.
	h.configMutationMu.RLock()
	snapshot := cloneManagementAPIConfig(h.currentConfig().APISec.ManagementAPI)
	interval := h.managementTokenFlushInterval
	h.configMutationMu.RUnlock()

	claims, ok := middleware.VerifyManagementAPIToken(raw, snapshot, at)
	if !ok {
		return nil, nil, false
	}
	if interval <= 0 {
		interval = time.Minute
	}
	needsTouch := false
	for _, token := range snapshot.Tokens {
		if token.ID != claims.ID {
			continue
		}
		if token.LastUsedAt.IsZero() || at.Sub(token.LastUsedAt) >= interval {
			needsTouch = true
		}
		break
	}
	if !needsTouch {
		return claims, nil, true
	}
	tokenID := claims.ID

	h.configMutationMu.Lock()
	// Re-check revoke/enabled for the race window, then publish a cloned
	// snapshot. Atomic snapshots are immutable and must never be edited in place.
	candidate, cloneErr := config.Clone(h.currentConfig())
	if cloneErr != nil {
		h.configMutationMu.Unlock()
		return nil, nil, false
	}
	updated := false
	found := false
	for idx := range candidate.APISec.ManagementAPI.Tokens {
		token := &candidate.APISec.ManagementAPI.Tokens[idx]
		if token.ID != tokenID {
			continue
		}
		found = true
		if !token.Enabled || !token.RevokedAt.IsZero() {
			h.configMutationMu.Unlock()
			return nil, nil, false
		}
		if !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(at) {
			h.configMutationMu.Unlock()
			return nil, nil, false
		}
		if token.LastUsedAt.IsZero() || at.Sub(token.LastUsedAt) >= interval {
			token.LastUsedAt = at
			updated = true
		}
		break
	}
	if !found {
		h.configMutationMu.Unlock()
		return nil, nil, false
	}
	if updated {
		if err := h.publishConfig(candidate); err != nil {
			h.configMutationMu.Unlock()
			return nil, nil, false
		}
	}
	snapshot = cloneManagementAPIConfig(h.currentConfig().APISec.ManagementAPI)
	h.configMutationMu.Unlock()

	claims, ok = middleware.VerifyManagementAPIToken(raw, snapshot, at)
	if !ok {
		return nil, nil, false
	}
	if !updated || h.ConfigPath == "" {
		return claims, nil, true
	}
	return claims, func() {
		if err := h.persistManagementAPITokenUsageSnapshot(); err != nil {
			log.Printf("management api token usage flush failed: %v", err)
		}
	}, true
}

func cloneManagementAPIConfig(source config.ManagementAPIConfig) config.ManagementAPIConfig {
	cloned := config.ManagementAPIConfig{Enabled: source.Enabled}
	cloned.Tokens = make([]config.ManagementAPITokenConfig, len(source.Tokens))
	for index, token := range source.Tokens {
		cloned.Tokens[index] = token
		cloned.Tokens[index].Scopes = append([]string(nil), token.Scopes...)
	}
	return cloned
}

func (h *Handler) persistManagementAPITokenUsageSnapshot() error {
	if h == nil || h.ConfigPath == "" {
		return nil
	}
	h.configPersistMu.Lock()
	defer h.configPersistMu.Unlock()
	h.configMutationMu.RLock()
	snapshot, err := config.Clone(h.currentConfig())
	h.configMutationMu.RUnlock()
	if err != nil {
		return err
	}
	return config.Save(h.ConfigPath, snapshot)
}

func (h *Handler) CreateManagementAPIToken(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	if h.currentConfig() == nil || !h.currentConfig().APISec.ManagementAPI.Enabled {
		writeError(w, http.StatusBadRequest, "API_TOKEN_DISABLED", "management api tokens are disabled")
		return
	}
	var req managementAPITokenPayload
	if !decode(w, r, &req) {
		return
	}
	name := req.Name
	if !validTokenDisplayText(name, true) {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token name is required")
		return
	}
	if !validTokenDisplayText(req.Notes, false) {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token notes contain control characters")
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
	now := h.nowUTC()
	lifetime, ok := parseManagementAPITokenExpiry(w, r, req, now)
	if !ok {
		return
	}
	var releaseConfirmation func(bool)
	if req.NeverExpire {
		confirmationID := req.ConfirmationID
		if err := validateManagementTokenConfirmationID(confirmationID); err != nil {
			writeError(w, http.StatusBadRequest, "API_TOKEN_CONFIRMATION_REQUIRED", err.Error())
			return
		}
		if h.managementTokenConfirmationVerifier == nil {
			writeError(w, http.StatusNotImplemented, "API_TOKEN_CONFIRMATION_UNAVAILABLE", "non-expiring management tokens are disabled until password/TOTP, warning-delay, local-session and approval checks are configured")
			return
		}
		if err := h.managementTokenConfirmationVerifier(r, ManagementTokenConfirmation{
			ConfirmationID:     req.ConfirmationID,
			WarningReadAt:      req.WarningReadAt,
			Password:           req.Password,
			TOTPCode:           req.TOTPCode,
			SecondConfirmation: req.SecondConfirmation,
			ConfirmationPhrase: req.ConfirmationPhrase,
		}, now); err != nil {
			if errors.Is(err, errManagementAPITokenConfirmationReplay) {
				writeError(w, http.StatusConflict, "API_TOKEN_CONFIRMATION_REPLAY", err.Error())
			} else {
				writeError(w, http.StatusForbidden, "API_TOKEN_CONFIRMATION_REJECTED", err.Error())
			}
			return
		}
		var err error
		releaseConfirmation, err = h.reserveManagementTokenConfirmation(confirmationID, now)
		if err != nil {
			writeError(w, http.StatusConflict, "API_TOKEN_CONFIRMATION_REPLAY", err.Error())
			return
		}
	}
	raw, err := newManagementAPITokenSecret()
	if err != nil {
		if releaseConfirmation != nil {
			releaseConfirmation(true)
		}
		writeError(w, http.StatusInternalServerError, "API_TOKEN_GENERATE_FAILED", err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	item := config.ManagementAPITokenConfig{
		ID:          uuid.NewString(),
		Name:        name,
		Prefix:      managementAPITokenDisplayPrefix(raw),
		Hash:        middleware.HashManagementAPIToken(raw),
		Scopes:      scopes,
		Notes:       req.Notes,
		Enabled:     enabled,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   lifetime.ExpiresAt,
		NeverExpire: lifetime.NeverExpire,
	}

	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		if len(candidate.APISec.ManagementAPI.Tokens) >= config.MaxManagementAPITokens {
			return errManagementAPITokenCapacity
		}
		active := 0
		for _, token := range candidate.APISec.ManagementAPI.Tokens {
			if token.Enabled && token.RevokedAt.IsZero() && (token.ExpiresAt.IsZero() || token.ExpiresAt.After(now)) {
				active++
			}
		}
		if active >= config.MaxActiveManagementAPITokens {
			return errManagementAPITokenCapacity
		}
		candidate.APISec.ManagementAPI.Tokens = append(candidate.APISec.ManagementAPI.Tokens, item)
		if err := config.Validate(candidate); err != nil {
			return fmt.Errorf("%w: %v", errManagementAPITokenConfigInvalid, err)
		}
		return nil
	}, nil)
	if err != nil {
		if releaseConfirmation != nil {
			releaseConfirmation(true)
		}
		if errors.Is(err, errManagementAPITokenCapacity) {
			writeError(w, http.StatusConflict, "API_TOKEN_CAPACITY", err.Error())
			return
		}
		if errors.Is(err, errManagementAPITokenConfigInvalid) {
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	if releaseConfirmation != nil {
		releaseConfirmation(false)
	}
	h.recordManagementTokenCreation(now)
	created := committed.APISec.ManagementAPI.Tokens[len(committed.APISec.ManagementAPI.Tokens)-1]
	writeData(w, map[string]any{"token": raw, "item": managementAPITokenViewFromConfig(created)})
}

func (h *Handler) RevokeManagementAPIToken(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if !strictTokenIdentity(id) {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token id is required")
		return
	}
	now := h.nowUTC()
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

func parseManagementAPITokenExpiry(w http.ResponseWriter, r *http.Request, req managementAPITokenPayload, now time.Time) (tokens.Lifetime, bool) {
	var ttl time.Duration
	var err error
	if strings.TrimSpace(req.TTL) != "" {
		ttl, err = time.ParseDuration(strings.TrimSpace(req.TTL))
		if err != nil {
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "ttl must be a duration such as 1h or 720h")
			return tokens.Lifetime{}, false
		}
	}
	var expiresAt time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		expiresAt, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "expires_at must be RFC3339 time")
			return tokens.Lifetime{}, false
		}
	}
	if req.NeverExpire && r != nil {
		claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
		if claims == nil || claims.Role != "admin" {
			writeError(w, http.StatusForbidden, "API_TOKEN_CONFIRMATION_REQUIRED", "only an administrator session may confirm a non-expiring management token")
			return tokens.Lifetime{}, false
		}
	}
	lifetime, err := tokens.ResolveLifetime(now, ttl, expiresAt, req.NeverExpire, req.ConfirmNeverExpire)
	if err != nil {
		switch {
		case errors.Is(err, tokens.ErrSecondConfirmationRequired):
			writeError(w, http.StatusBadRequest, "API_TOKEN_CONFIRMATION_REQUIRED", "never_expire requires confirm_never_expire and a one-time confirmation_id")
		case errors.Is(err, tokens.ErrTTLExceeded):
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "token lifetime must not exceed 365 days")
		default:
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
		}
		return tokens.Lifetime{}, false
	}
	if !req.NeverExpire && req.ConfirmNeverExpire {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "confirm_never_expire is only valid with never_expire")
		return tokens.Lifetime{}, false
	}
	return lifetime, true
}

func normalizeScopes(scopes []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !strictTokenIdentity(scope) {
			return nil
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

func validateManagementTokenConfirmationID(id string) error {
	if id == "" {
		return errManagementAPITokenConfirmationRequired
	}
	if len(id) > 128 || !strictTokenIdentity(id) {
		return fmt.Errorf("confirmation_id must be 1-128 non-whitespace characters")
	}
	return nil
}

// reserveManagementTokenConfirmation provides a one-time replay barrier for
// the API boundary. Password/TOTP verification belongs to the approval/session
// layer; this local reservation prevents a duplicate request racing that layer
// from creating more than one non-expiring token.
func (h *Handler) reserveManagementTokenConfirmation(id string, now time.Time) (func(bool), error) {
	if h == nil {
		return nil, errManagementAPITokenConfirmationRequired
	}
	h.managementTokenConfirmationsMu.Lock()
	defer h.managementTokenConfirmationsMu.Unlock()
	if h.managementTokenConfirmations == nil {
		h.managementTokenConfirmations = make(map[string]time.Time)
	}
	cutoff := now.Add(-managementTokenConfirmationRetention)
	for existing, at := range h.managementTokenConfirmations {
		if at.Before(cutoff) {
			delete(h.managementTokenConfirmations, existing)
		}
	}
	if _, used := h.managementTokenConfirmations[id]; used {
		return nil, errManagementAPITokenConfirmationReplay
	}
	h.managementTokenConfirmations[id] = now
	return func(rollback bool) {
		if !rollback {
			return
		}
		h.managementTokenConfirmationsMu.Lock()
		if at, ok := h.managementTokenConfirmations[id]; ok && at.Equal(now) {
			delete(h.managementTokenConfirmations, id)
		}
		h.managementTokenConfirmationsMu.Unlock()
	}, nil
}

func (h *Handler) validateManagementAPITokenScopes(r *http.Request, scopes []string) error {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil {
		return fmt.Errorf("caller is not authenticated")
	}
	permissions := config.Default().APISec.Permissions
	if h != nil && h.currentConfig() != nil && len(h.currentConfig().APISec.Permissions) > 0 {
		permissions = h.currentConfig().APISec.Permissions
	}
	for _, scope := range scopes {
		if scope == "*" {
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
	if !strictTokenIdentity(permission) || !strictTokenIdentity(required) {
		return false
	}
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
	if len(raw) <= 18 {
		return raw
	}
	return raw[:18]
}

func strictTokenIdentity(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func hasDisplayText(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func validTokenDisplayText(value string, required bool) bool {
	if required && !hasDisplayText(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
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
		ID:          token.ID,
		Name:        token.Name,
		Prefix:      token.Prefix,
		Scopes:      append([]string(nil), token.Scopes...),
		Notes:       token.Notes,
		Enabled:     token.Enabled && token.RevokedAt.IsZero(),
		CreatedAt:   token.CreatedAt,
		UpdatedAt:   token.UpdatedAt,
		LastUsedAt:  token.LastUsedAt,
		ExpiresAt:   token.ExpiresAt,
		RevokedAt:   token.RevokedAt,
		NeverExpire: token.NeverExpire || token.ExpiresAt.IsZero(),
	}
}
