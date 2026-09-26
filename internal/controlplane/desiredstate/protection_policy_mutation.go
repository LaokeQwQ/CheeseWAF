package desiredstate

import (
	"errors"
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

// ErrProtectionPolicyMutationInvalid identifies caller-supplied mutation data
// that cannot be accepted as a protection-policy update. HTTP adapters should
// map this class of error to a client-side 400 response.
var ErrProtectionPolicyMutationInvalid = errors.New("invalid protection policy mutation")

// ProtectionPolicyMutationValidationError describes one invalid mutation
// input without requiring callers to parse an error string.
type ProtectionPolicyMutationValidationError struct {
	Field  string
	Value  string
	Reason string
}

func (e ProtectionPolicyMutationValidationError) Error() string {
	if e.Field == "" {
		if e.Reason == "" {
			return ErrProtectionPolicyMutationInvalid.Error()
		}
		return e.Reason
	}
	if e.Value == "" {
		return fmt.Sprintf("invalid protection policy mutation for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("invalid protection policy mutation for %s: %q: %s", e.Field, e.Value, e.Reason)
}

func (e ProtectionPolicyMutationValidationError) Unwrap() error {
	return ErrProtectionPolicyMutationInvalid
}

// ProtectionPolicyPatch is the field-presence-aware input accepted by future
// management write paths. A nil field means "keep the current value"; a
// non-nil field is applied exactly as supplied and must be a valid protection
// level. The patch is deliberately narrower than config.ProtectionConfig.
type ProtectionPolicyPatch struct {
	WebAttack   *string `json:"web_attack,omitempty"`
	APISecurity *string `json:"api_security,omitempty"`
	BotCC       *string `json:"bot_cc,omitempty"`
	ThreatIntel *string `json:"threat_intel,omitempty"`
}

// ProtectionPolicyMutationRequest contains the caller and CAS metadata needed
// to construct a control-plane proposal. Actor is retained in the result for
// the eventual audit/approval layer; it is not placed in the replicated
// protection-policy payload. Identity fields are validated without trimming.
type ProtectionPolicyMutationRequest struct {
	Actor            string                `json:"actor"`
	LeaderID         string                `json:"leader_id"`
	ExpectedEpoch    controlplane.Epoch    `json:"expected_epoch"`
	ExpectedRevision controlplane.Revision `json:"expected_revision"`
	Nonce            string                `json:"nonce"`
	Patch            ProtectionPolicyPatch `json:"patch"`
}

// ProtectionPolicyMutation is the side-effect-free result of preparing a
// policy write. The caller may inspect Before/After, then submit Proposal to
// Coordinator. This service never persists, publishes, reloads or mutates the
// supplied current policy.
type ProtectionPolicyMutation struct {
	Actor    string
	Before   config.ProtectionPolicyConfig
	After    config.ProtectionPolicyConfig
	Proposal controlplane.Proposal
}

// ProtectionPolicyMutator is the narrow contract shared by future HTTP and AI
// mutation adapters. Implementations must only prepare a complete policy and
// canonical proposal; external side effects belong to the coordinator and
// materializer layers.
type ProtectionPolicyMutator interface {
	Prepare(current config.ProtectionPolicyConfig, request ProtectionPolicyMutationRequest) (ProtectionPolicyMutation, error)
}

// ProtectionPolicyMutationService prepares protection-policy mutations. It is
// stateless so one instance can be shared by all write adapters.
type ProtectionPolicyMutationService struct{}

var _ ProtectionPolicyMutator = ProtectionPolicyMutationService{}

// NewProtectionPolicyMutationService constructs the pure mutation service.
func NewProtectionPolicyMutationService() ProtectionPolicyMutationService {
	return ProtectionPolicyMutationService{}
}

// Prepare merges a partial patch into the current policy, validates strict
// caller/leader/nonce identities, and constructs the only canonical proposal
// shape accepted for protection-policy desired state.
func (ProtectionPolicyMutationService) Prepare(current config.ProtectionPolicyConfig, request ProtectionPolicyMutationRequest) (ProtectionPolicyMutation, error) {
	if !controlplane.ValidIdentity(request.Actor) {
		return ProtectionPolicyMutation{}, ProtectionPolicyMutationValidationError{Field: "actor", Reason: "strict identity is required"}
	}
	if !controlplane.ValidIdentity(request.LeaderID) {
		return ProtectionPolicyMutation{}, ProtectionPolicyMutationValidationError{Field: "leader_id", Reason: "strict identity is required"}
	}
	if !controlplane.ValidIdentity(request.Nonce) {
		return ProtectionPolicyMutation{}, ProtectionPolicyMutationValidationError{Field: "nonce", Reason: "strict identity is required"}
	}

	before := current.WithDefaults(config.DefaultProtectionPolicy())
	if _, err := NewProtectionPolicyDocument(before); err != nil {
		return ProtectionPolicyMutation{}, ProtectionPolicyMutationValidationError{Field: "current", Reason: "current protection policy is invalid: " + err.Error()}
	}
	after := before
	if err := applyProtectionPolicyPatch(&after, request.Patch); err != nil {
		return ProtectionPolicyMutation{}, err
	}
	proposal, err := NewProtectionPolicyProposal(after, request.LeaderID, request.ExpectedEpoch, request.ExpectedRevision, request.Nonce)
	if err != nil {
		return ProtectionPolicyMutation{}, err
	}
	return ProtectionPolicyMutation{Actor: request.Actor, Before: before, After: after, Proposal: proposal}, nil
}

// PrepareProtectionPolicyMutation is a convenience wrapper for callers that
// do not need to retain a service value.
func PrepareProtectionPolicyMutation(current config.ProtectionPolicyConfig, request ProtectionPolicyMutationRequest) (ProtectionPolicyMutation, error) {
	return ProtectionPolicyMutationService{}.Prepare(current, request)
}

func applyProtectionPolicyPatch(policy *config.ProtectionPolicyConfig, patch ProtectionPolicyPatch) error {
	if policy == nil {
		return ProtectionPolicyMutationValidationError{Field: "policy", Reason: "policy is nil"}
	}
	fields := []struct {
		name  string
		value *string
		apply func(string)
	}{
		{name: "web_attack", value: patch.WebAttack, apply: func(value string) { policy.WebAttack = value }},
		{name: "api_security", value: patch.APISecurity, apply: func(value string) { policy.APISecurity = value }},
		{name: "bot_cc", value: patch.BotCC, apply: func(value string) { policy.BotCC = value }},
		{name: "threat_intel", value: patch.ThreatIntel, apply: func(value string) { policy.ThreatIntel = value }},
	}
	for _, field := range fields {
		if field.value == nil {
			continue
		}
		if !config.IsProtectionLevel(*field.value) || *field.value == "" {
			return ProtectionPolicyMutationValidationError{Field: field.name, Value: *field.value, Reason: "must be one of off, low, smart, high, or strict"}
		}
		field.apply(*field.value)
	}
	return nil
}
