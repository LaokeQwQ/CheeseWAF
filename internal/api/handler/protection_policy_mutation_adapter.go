package handler

import (
	"errors"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

// ErrProtectionPolicyMutationUnavailable indicates that the desired-state
// mutation seam was not deliberately wired by the owning runtime. Returning
// this error keeps future adapters fail-closed instead of silently falling
// back to the legacy local config writer.
var ErrProtectionPolicyMutationUnavailable = errors.New("protection policy mutation service is unavailable")

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
