package desiredstate

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

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
		return ProtectionPolicyMutation{}, fmt.Errorf("protection policy mutation requires a strict actor identity")
	}
	if !controlplane.ValidIdentity(request.LeaderID) {
		return ProtectionPolicyMutation{}, fmt.Errorf("protection policy mutation requires a strict leader identity")
	}
	if !controlplane.ValidIdentity(request.Nonce) {
		return ProtectionPolicyMutation{}, fmt.Errorf("protection policy mutation requires a strict nonce identity")
	}

	before := current.WithDefaults(config.DefaultProtectionPolicy())
	if _, err := NewProtectionPolicyDocument(before); err != nil {
		return ProtectionPolicyMutation{}, fmt.Errorf("current protection policy is invalid: %w", err)
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
		return fmt.Errorf("protection policy is nil")
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
			return fmt.Errorf("invalid protection policy level for %s: %q", field.name, *field.value)
		}
		field.apply(*field.value)
	}
	return nil
}
