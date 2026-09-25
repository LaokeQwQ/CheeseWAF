package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

// ErrProtectionPolicyMutationUnavailable indicates that the desired-state
// mutation seam was not deliberately wired by the owning runtime. Returning
// this error keeps future adapters fail-closed instead of silently falling
// back to the legacy local config writer.
var ErrProtectionPolicyMutationUnavailable = errors.New("protection policy mutation service is unavailable")

// ErrProtectionPolicyCoordinatorUnavailable indicates that the end-to-end
// control-plane consumer was not deliberately wired. HTTP and AI write paths
// must surface this as unavailable instead of falling back to the node-local
// YAML/runtime writer.
var ErrProtectionPolicyCoordinatorUnavailable = errors.New("protection policy coordinator consumer is unavailable")

// ErrProtectionPolicyCoordinatorPreviewUnavailable indicates that a wired
// policy consumer cannot bind an AI approval to a control-plane snapshot.
// The AI path must refuse the mutation rather than fall back to a local diff.
var ErrProtectionPolicyCoordinatorPreviewUnavailable = errors.New("protection policy coordinator preview is unavailable")

// ProtectionPolicyCoordinatorConsumer owns the complete protection-policy
// lifecycle after an authenticated caller supplies a field-presence patch:
// control-plane snapshot/fencing, nonce generation, consensus + durable
// commit, and node-local materialization. Handler must not implement any of
// those steps or accept fencing metadata from the request body.
//
// The returned mutation is the non-sensitive policy result. Implementations
// must not require the caller to provide a nonce, leader, epoch, revision, or
// local configuration snapshot.
type ProtectionPolicyCoordinatorConsumer interface {
	ProposeAndApply(context.Context, string, desiredstate.ProtectionPolicyPatch) (desiredstate.ProtectionPolicyCoordinationResult, error)
}

// ProtectionPolicyCoordinatorPreviewConsumer extends the write consumer with
// a snapshot-bound preview and an apply method that enforces its opaque
// binding. This prevents an approved AI diff from silently applying to a
// newer control-plane state.
type ProtectionPolicyCoordinatorPreviewConsumer interface {
	ProtectionPolicyCoordinatorConsumer
	Preview(context.Context, string, desiredstate.ProtectionPolicyPatch) (desiredstate.ProtectionPolicyCoordinationPreview, error)
	ProposeAndApplyWithPreview(context.Context, string, desiredstate.ProtectionPolicyPatch, string) (desiredstate.ProtectionPolicyCoordinationResult, error)
}

func (h *Handler) protectionPolicyCoordinatorOrError(w http.ResponseWriter) ProtectionPolicyCoordinatorConsumer {
	if h == nil || h.protectionPolicyCoordinator == nil {
		writeError(w, http.StatusServiceUnavailable, "PROTECTION_POLICY_UNAVAILABLE", ErrProtectionPolicyCoordinatorUnavailable.Error())
		return nil
	}
	return h.protectionPolicyCoordinator
}

func protectionPolicyActorFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || !controlplane.ValidIdentity(claims.Subject) {
		return "", false
	}
	return claims.Subject, true
}

func writeProtectionPolicyCoordinatorError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	code := "PROTECTION_POLICY_UNAVAILABLE"
	if errors.Is(err, desiredstate.ErrProtectionPolicyMutationInvalid) || errors.Is(err, controlplane.ErrInvalidProposal) {
		status = http.StatusBadRequest
		code = "PROTECTION_POLICY_INVALID"
	} else if errors.Is(err, controlplane.ErrNotLeader) ||
		errors.Is(err, controlplane.ErrStaleEpoch) ||
		errors.Is(err, controlplane.ErrStaleRevision) ||
		errors.Is(err, controlplane.ErrStaleFence) ||
		errors.Is(err, controlplane.ErrWritesFrozen) {
		status = http.StatusConflict
		code = "PROTECTION_POLICY_CONFLICT"
	}
	writeError(w, status, code, err.Error())
}

// PrepareProtectionPolicyMutation prepares a desired-state proposal from the
// handler's immutable policy snapshot. This method has no persistence,
// runtime-apply, HTTP, or coordinator side effects. The current production
// router leaves the mutator unset; a later lifecycle owner may inject it once
// proposal submission and materialization are fully wired.
func (h *Handler) PrepareProtectionPolicyMutation(request desiredstate.ProtectionPolicyMutationRequest) (desiredstate.ProtectionPolicyMutation, error) {
	if h == nil {
		return desiredstate.ProtectionPolicyMutation{}, errors.New("handler is nil")
	}
	if h.protectionPolicyMutator == nil {
		return desiredstate.ProtectionPolicyMutation{}, ErrProtectionPolicyMutationUnavailable
	}
	current := h.currentConfig()
	if current == nil {
		return desiredstate.ProtectionPolicyMutation{}, errors.New("handler config is unavailable")
	}
	return h.protectionPolicyMutator.Prepare(current.Protection.Policy, request)
}
