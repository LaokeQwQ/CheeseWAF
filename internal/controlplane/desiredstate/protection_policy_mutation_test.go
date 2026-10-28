package desiredstate

import (
	"errors"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

func stringPtr(value string) *string { return &value }

func TestProtectionPolicyMutationMergesPartialPatchAndBuildsProposal(t *testing.T) {
	current := config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelLow,
		APISecurity: config.ProtectionLevelHigh,
		BotCC:       config.ProtectionLevelSmart,
		ThreatIntel: config.ProtectionLevelOff,
	}
	request := ProtectionPolicyMutationRequest{
		Actor:            "operator-a",
		LeaderID:         "node-a",
		ExpectedEpoch:    4,
		ExpectedRevision: 9,
		Nonce:            "request-9",
		Patch: ProtectionPolicyPatch{
			WebAttack:   stringPtr(config.ProtectionLevelStrict),
			ThreatIntel: stringPtr(config.ProtectionLevelHigh),
		},
	}

	mutation, err := NewProtectionPolicyMutationService().Prepare(current, request)
	if err != nil {
		t.Fatal(err)
	}
	want := config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelStrict,
		APISecurity: config.ProtectionLevelHigh,
		BotCC:       config.ProtectionLevelSmart,
		ThreatIntel: config.ProtectionLevelHigh,
	}
	if mutation.Actor != request.Actor || mutation.Before != current || mutation.After != want {
		t.Fatalf("mutation = %+v, want actor=%q before=%+v after=%+v", mutation, request.Actor, current, want)
	}
	if mutation.Proposal.LeaderID != request.LeaderID || mutation.Proposal.ExpectedEpoch != request.ExpectedEpoch || mutation.Proposal.ExpectedRevision != request.ExpectedRevision || mutation.Proposal.Nonce != request.Nonce {
		t.Fatalf("proposal metadata = %+v, request = %+v", mutation.Proposal, request)
	}
	if err := ValidateProtectionPolicyProposal(mutation.Proposal); err != nil {
		t.Fatalf("proposal validation failed: %v", err)
	}
	decoded, err := DecodeProtectionPolicyConfig(mutation.Proposal.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != want {
		t.Fatalf("proposal policy = %+v, want %+v", decoded, want)
	}
}

func TestProtectionPolicyMutationAppliesDefaultsBeforeMerging(t *testing.T) {
	mutation, err := PrepareProtectionPolicyMutation(config.ProtectionPolicyConfig{}, ProtectionPolicyMutationRequest{
		Actor:    "operator-a",
		LeaderID: "node-a",
		Nonce:    "request-1",
		Patch: ProtectionPolicyPatch{
			BotCC: stringPtr(config.ProtectionLevelOff),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defaults := config.DefaultProtectionPolicy()
	defaults.BotCC = config.ProtectionLevelOff
	if mutation.Before != config.DefaultProtectionPolicy() || mutation.After != defaults {
		t.Fatalf("before=%+v after=%+v, want defaults then patch=%+v", mutation.Before, mutation.After, defaults)
	}
}

func TestProtectionPolicyMutationRejectsInvalidPatchWithoutProposal(t *testing.T) {
	cases := map[string]*string{
		"empty":   stringPtr(""),
		"invalid": stringPtr("block"),
	}
	for name, level := range cases {
		t.Run(name, func(t *testing.T) {
			mutation, err := PrepareProtectionPolicyMutation(validPolicy(), ProtectionPolicyMutationRequest{
				Actor:    "operator-a",
				LeaderID: "node-a",
				Nonce:    "request-1",
				Patch:    ProtectionPolicyPatch{WebAttack: level},
			})
			if err == nil {
				t.Fatalf("mutation unexpectedly succeeded: %+v", mutation)
			}
			var validationErr ProtectionPolicyMutationValidationError
			if !errors.As(err, &validationErr) || !errors.Is(err, ErrProtectionPolicyMutationInvalid) {
				t.Fatalf("error=%T %v, want typed mutation validation error", err, err)
			}
			if validationErr.Field != "web_attack" || validationErr.Value != *level {
				t.Fatalf("validation error=%+v, want web_attack=%q", validationErr, *level)
			}
		})
	}
}

func TestProtectionPolicyMutationRejectsNonCanonicalIdentities(t *testing.T) {
	cases := []struct {
		name string
		make func() ProtectionPolicyMutationRequest
	}{
		{name: "actor leading space", make: func() ProtectionPolicyMutationRequest {
			return ProtectionPolicyMutationRequest{Actor: " operator-a", LeaderID: "node-a", Nonce: "nonce-1"}
		}},
		{name: "leader trailing tab", make: func() ProtectionPolicyMutationRequest {
			return ProtectionPolicyMutationRequest{Actor: "operator-a", LeaderID: "node-a\t", Nonce: "nonce-1"}
		}},
		{name: "nonce control", make: func() ProtectionPolicyMutationRequest {
			return ProtectionPolicyMutationRequest{Actor: "operator-a", LeaderID: "node-a", Nonce: "nonce\n1"}
		}},
		{name: "nonce invisible format", make: func() ProtectionPolicyMutationRequest {
			return ProtectionPolicyMutationRequest{Actor: "operator-a", LeaderID: "node-a", Nonce: "nonce\u200b1"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PrepareProtectionPolicyMutation(validPolicy(), tc.make()); err == nil {
				t.Fatal("non-canonical identity unexpectedly accepted")
			}
		})
	}
}

func TestProtectionPolicyMutationRejectsInvalidCurrentPolicy(t *testing.T) {
	current := validPolicy()
	current.APISecurity = "unsafe"
	_, err := PrepareProtectionPolicyMutation(current, ProtectionPolicyMutationRequest{
		Actor:    "operator-a",
		LeaderID: "node-a",
		Nonce:    "nonce-1",
	})
	if err == nil || !strings.Contains(err.Error(), "current protection policy") {
		t.Fatalf("error = %v, want invalid current policy error", err)
	}
}

func TestProtectionPolicyMutationDoesNotChangeInputPolicy(t *testing.T) {
	current := config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelLow,
		APISecurity: config.ProtectionLevelSmart,
		BotCC:       config.ProtectionLevelHigh,
		ThreatIntel: config.ProtectionLevelOff,
	}
	want := current
	_, err := PrepareProtectionPolicyMutation(current, ProtectionPolicyMutationRequest{
		Actor:    "operator-a",
		LeaderID: "node-a",
		Nonce:    "nonce-1",
		Patch:    ProtectionPolicyPatch{WebAttack: stringPtr(config.ProtectionLevelStrict)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if current != want {
		t.Fatalf("current policy changed: got %+v want %+v", current, want)
	}
}

func TestProtectionPolicyMutationProposalUsesCanonicalPayload(t *testing.T) {
	mutation, err := PrepareProtectionPolicyMutation(validPolicy(), ProtectionPolicyMutationRequest{
		Actor:    "operator-a",
		LeaderID: "node-a",
		Nonce:    "nonce-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Proposal.Version != Version || mutation.Proposal.Digest != controlplane.Digest(mutation.Proposal.Payload) {
		t.Fatalf("proposal is not digest-bound: %+v", mutation.Proposal)
	}
	if string(mutation.Proposal.Payload) != `{"version":"management.v1","kind":"protection.policy","spec":{"web_attack":"smart","api_security":"high","bot_cc":"low","threat_intel":"off"}}` {
		t.Fatalf("proposal payload is not canonical: %s", mutation.Proposal.Payload)
	}
}
