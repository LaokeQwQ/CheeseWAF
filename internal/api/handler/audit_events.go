package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/google/uuid"
)

var ErrAuditRuntimeUnavailable = errors.New("durable audit runtime is unavailable")

const crpAuditAppendTimeout = 5 * time.Second

// appendCRPActivationAudit emits only stable identifiers and reason codes.
// Request bodies, descriptor fields, paths, and backend errors never enter the
// durable hash chain.
func (h *Handler) appendCRPActivationAudit(ctx context.Context, claims *middleware.Claims, action, pluginKey, correlationID, authorizationID, confirmationID string, outcome audit.Outcome, reason string) error {
	if h == nil || h.AuditRuntime == nil {
		if h != nil && h.RequireAuditRuntime {
			return ErrAuditRuntimeUnavailable
		}
		return nil
	}
	actor, ok := crpAuditActor(claims)
	if !ok || h.AuditPolicyEpoch == 0 {
		return ErrAuditRuntimeUnavailable
	}
	digest := sha256.Sum256([]byte(pluginKey))
	digestText := hex.EncodeToString(digest[:])
	if ctx == nil {
		ctx = context.Background()
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), crpAuditAppendTimeout)
	defer cancel()
	_, err := h.AuditRuntime.Append(auditCtx, audit.Event{
		EventID:         uuid.NewString(),
		StreamID:        "management",
		TenantID:        "tenant:local",
		Actor:           actor,
		Type:            audit.EventTypeAuthorization,
		Action:          "crp." + action,
		Resource:        "crp/plugin/" + digestText,
		Outcome:         outcome,
		CorrelationID:   correlationID,
		AuthorizationID: authorizationID,
		SessionID:       claims.ID,
		ConfirmationID:  confirmationID,
		Reason:          reason,
		EvidenceDigest:  digestText,
		PolicyEpoch:     h.AuditPolicyEpoch,
		Class:           audit.EventClassCritical,
		At:              h.nowUTC(),
	})
	return err
}

func crpAuditActor(claims *middleware.Claims) (string, bool) {
	if claims == nil || claims.Subject == "" || claims.ID == "" || claims.Role == "" {
		return "", false
	}
	if auditIdentifier(claims.Role) && auditIdentifier(claims.Subject) {
		return claims.Role + ":" + claims.Subject, true
	}
	digest := sha256.Sum256([]byte(claims.Role + "\x00" + claims.Subject))
	return "principal-hash:" + hex.EncodeToString(digest[:]), true
}

func auditIdentifier(value string) bool {
	if value == "" || strings.Contains(value, "://") {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-:@/", r) {
			continue
		}
		return false
	}
	return true
}
