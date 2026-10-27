package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
	tokensservice "github.com/LaokeQwQ/CheeseWAF/internal/tokens/service"
	"github.com/google/uuid"
)

// durableManagementTokenRawPrefix is the on-the-wire prefix for tokens issued by
// the durable service. The legacy config path keeps its opaque per-token prefix.
const (
	durableManagementTokenRawPrefix = middleware.ManagementAPITokenPrefix
	// durableManagementTokenSeparator separates the token id from the secret.
	// Token ids are "tok_<hex>", so '_' cannot be used: it is ambiguous.
	durableManagementTokenSeparator = "~"
)

func (h *Handler) managementTokenTenant() string {
	if h == nil || h.currentConfig() == nil {
		return "default"
	}
	if durable := h.currentConfig().APISec.ManagementAPI.Durable; durable != nil && durable.TenantID != "" {
		return durable.TenantID
	}
	return "default"
}

func (h *Handler) managementTokenActor(r *http.Request) string {
	if claims, ok := r.Context().Value(middleware.UserContextKey).(*middleware.Claims); ok && claims != nil {
		if claims.Username != "" {
			return claims.Username
		}
		if claims.Subject != "" {
			return claims.Subject
		}
	}
	return "system"
}

func (h *Handler) managementTokenPolicyEpoch() uint64 {
	if h == nil || h.PolicyEpoch == 0 {
		return 1
	}
	return h.PolicyEpoch
}

func splitManagementTokenScopes(scopes []string) (permissions, resources []string, ok bool) {
	for _, scope := range scopes {
		action, resource, found := strings.Cut(strings.TrimSpace(scope), ":")
		if !found || action == "" || resource == "" {
			return nil, nil, false
		}
		permissions = append(permissions, action)
		resources = append(resources, resource)
	}
	return permissions, resources, len(permissions) > 0
}

func managementAPITokenViewFromMetadata(meta tokens.Metadata) managementAPITokenView {
	scopes := meta.Scopes
	if len(scopes) == 0 {
		scopes = meta.Resources
	}
	return managementAPITokenView{
		ID:          meta.ID,
		Name:        meta.Name,
		Scopes:      append([]string(nil), scopes...),
		Notes:       meta.Note,
		Enabled:     !meta.Disabled && !meta.Revoked,
		CreatedAt:   meta.CreatedAt,
		UpdatedAt:   meta.LastActivityAt,
		LastUsedAt:  meta.LastActivityAt,
		ExpiresAt:   meta.ExpiresAt,
		NeverExpire: meta.NeverExpire,
	}
}

func (h *Handler) listDurableManagementTokens(ctx context.Context) ([]managementAPITokenView, error) {
	items, err := h.TokenService.List(ctx, h.managementTokenTenant())
	if err != nil {
		return nil, err
	}
	views := make([]managementAPITokenView, 0, len(items))
	for _, item := range items {
		views = append(views, managementAPITokenViewFromMetadata(item))
	}
	return views, nil
}

// createDurableManagementAPIToken issues a token through the durable service and
// returns the plaintext exactly once. The caller has already validated the name,
// notes, scopes and lifetime.
func (h *Handler) createDurableManagementAPIToken(w http.ResponseWriter, r *http.Request, name, notes string, scopes []string, lifetime tokens.Lifetime, now time.Time) {
	permissions, resources, ok := splitManagementTokenScopes(scopes)
	if !ok {
		writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", "every scope must use action:resource format")
		return
	}
	issued, err := h.TokenService.Issue(r.Context(), tokensservice.IssueRequest{
		TenantID:       h.managementTokenTenant(),
		IdempotencyKey: uuid.NewString(),
		Request: tokens.CreateRequest{
			Owner:       h.managementTokenActor(r),
			Name:        name,
			Permissions: permissions,
			Resources:   resources,
			Note:        notes,
			PolicyEpoch: h.managementTokenPolicyEpoch(),
			NeverExpire: lifetime.NeverExpire,
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, tokensservice.ErrConfirmationUnavailable), errors.Is(err, tokensservice.ErrConfirmationRequired):
			writeError(w, http.StatusNotImplemented, "API_TOKEN_CONFIRMATION_UNAVAILABLE", "non-expiring management tokens are disabled until the durable confirmation gate is configured")
		case errors.Is(err, tokensservice.ErrInvalidRequest):
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
		case errors.Is(err, tokens.ErrTTLExceeded), errors.Is(err, tokens.ErrInvalidTTL):
			writeError(w, http.StatusBadRequest, "API_TOKEN_INVALID", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "API_TOKEN_STORE_ERROR", err.Error())
		}
		return
	}
	raw := durableManagementTokenRawPrefix + issued.Metadata.ID + durableManagementTokenSeparator + issued.Secret
	h.recordManagementTokenCreation(now)
	writeData(w, map[string]any{"token": raw, "item": managementAPITokenViewFromMetadata(issued.Metadata)})
}

func (h *Handler) revokeDurableManagementAPIToken(w http.ResponseWriter, r *http.Request, id string) {
	err := h.TokenService.Revoke(r.Context(), tokensservice.RevokeRequest{
		TenantID:       h.managementTokenTenant(),
		TokenID:        id,
		Actor:          h.managementTokenActor(r),
		PolicyEpoch:    h.managementTokenPolicyEpoch(),
		IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		if errors.Is(err, tokens.ErrNotFound) {
			writeError(w, http.StatusNotFound, "API_TOKEN_NOT_FOUND", "management api token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "API_TOKEN_STORE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"revoked": true})
}

// authenticateDurableManagementToken verifies a cwapi_<id>_<secret> bearer
// token against the durable store. It returns false for shapes it does not own
// so the legacy config-backed verifier keeps accepting pre-existing tokens.
func (h *Handler) authenticateDurableManagementToken(r *http.Request, raw string) (*middleware.Claims, bool) {
	if h == nil || h.TokenService == nil || r == nil {
		return nil, false
	}
	if !strings.HasPrefix(raw, durableManagementTokenRawPrefix) {
		return nil, false
	}
	tokenID, secret, found := strings.Cut(strings.TrimPrefix(raw, durableManagementTokenRawPrefix), durableManagementTokenSeparator)
	if !found || tokenID == "" || secret == "" {
		return nil, false
	}
	meta, err := h.TokenService.Authenticate(r.Context(), tokensservice.AuthenticateRequest{
		TenantID:       h.managementTokenTenant(),
		TokenID:        tokenID,
		Secret:         secret,
		PolicyEpoch:    h.managementTokenPolicyEpoch(),
		IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		return nil, false
	}
	scopes := make([]string, 0, len(meta.Permissions))
	for i, permission := range meta.Permissions {
		if i >= len(meta.Resources) {
			break
		}
		scopes = append(scopes, permission+":"+meta.Resources[i])
	}
	username := meta.Name
	if username == "" {
		username = meta.Owner
	}
	claims := &middleware.Claims{
		Subject:  meta.Owner,
		ID:       meta.ID,
		Username: username,
		Role:     "api-token",
		Scopes:   scopes,
		IssuedAt: meta.CreatedAt.Unix(),
	}
	if !meta.ExpiresAt.IsZero() {
		claims.Expires = meta.ExpiresAt.Unix()
	}
	return claims, true
}
