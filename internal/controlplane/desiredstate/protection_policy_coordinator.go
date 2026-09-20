package desiredstate

import (
	"context"
	"errors"
	"reflect"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

// ErrProtectionPolicyCoordinatorUnavailable indicates that the proposal
// submission boundary was not deliberately wired. Callers must surface this
// as unavailable; they must not fall back to a local config writer.
var ErrProtectionPolicyCoordinatorUnavailable = errors.New("protection policy coordinator service is unavailable")

// ProtectionPolicyCoordinationResult contains both the audit context and the
// exact control-plane commit. Commit is populated even when Coordinator
// returns a persistence error, so the caller can retry that exact commit with
// Apply without proposing a second nonce or revision.
type ProtectionPolicyCoordinationResult struct {
	Mutation ProtectionPolicyMutation
	Commit   controlplane.Commit
}

// ProtectionPolicyCoordinationPreview is an operator-visible mutation
// preview plus an opaque server-created binding. The binding is persisted only
// through the AI approval digest and must be checked again by the lifecycle
// owner immediately before applying the patch.
type ProtectionPolicyCoordinationPreview struct {
	Mutation ProtectionPolicyMutation
	Binding  string
}

// ProtectionPolicyCoordinatorService is the control-plane consumer for the
// pure protection-policy mutator. It intentionally has no HTTP, Handler,
// runtime, YAML or materializer dependency. The actor lives only in the
// returned mutation for authorization/audit handling and is never replicated
// in the desired-state payload.
type ProtectionPolicyCoordinatorService struct {
	mutator     ProtectionPolicyMutator
	coordinator *controlplane.Coordinator
}

// NewProtectionPolicyCoordinatorService constructs the proposal submission
// boundary. Missing dependencies are rejected before a service can be used;
// the zero value and nil receiver remain fail-closed as well.
func NewProtectionPolicyCoordinatorService(mutator ProtectionPolicyMutator, coordinator *controlplane.Coordinator) (*ProtectionPolicyCoordinatorService, error) {
	if isNilProtectionPolicyMutator(mutator) || coordinator == nil {
		return nil, ErrProtectionPolicyCoordinatorUnavailable
	}
	return &ProtectionPolicyCoordinatorService{mutator: mutator, coordinator: coordinator}, nil
}

// ProposeAndApply prepares a complete canonical protection-policy proposal and
// submits it through Coordinator. The current policy is supplied by the
// lifecycle owner as an immutable snapshot; this service does not read or
// mutate Handler/config state itself.
func (s *ProtectionPolicyCoordinatorService) ProposeAndApply(ctx context.Context, current config.ProtectionPolicyConfig, request ProtectionPolicyMutationRequest) (ProtectionPolicyCoordinationResult, error) {
	if s == nil || isNilProtectionPolicyMutator(s.mutator) || s.coordinator == nil {
		return ProtectionPolicyCoordinationResult{}, ErrProtectionPolicyCoordinatorUnavailable
	}
	mutation, err := s.mutator.Prepare(current, request)
	if err != nil {
		return ProtectionPolicyCoordinationResult{}, err
	}
	commit, err := s.coordinator.ProposeAndApply(ctx, mutation.Proposal)
	return ProtectionPolicyCoordinationResult{Mutation: mutation, Commit: commit}, err
}

// Apply retries the exact commit returned by ProposeAndApply after a
// persistence-stage failure. It deliberately does not call Prepare or create
// another proposal, preserving Coordinator's exact-commit idempotency rules.
func (s *ProtectionPolicyCoordinatorService) Apply(ctx context.Context, commit controlplane.Commit) error {
	if s == nil || isNilProtectionPolicyMutator(s.mutator) || s.coordinator == nil {
		return ErrProtectionPolicyCoordinatorUnavailable
	}
	return s.coordinator.Apply(ctx, commit)
}

func isNilProtectionPolicyMutator(mutator ProtectionPolicyMutator) bool {
	if mutator == nil {
		return true
	}
	v := reflect.ValueOf(mutator)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
