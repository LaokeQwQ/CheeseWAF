// Package desiredstate contains versioned, control-plane-owned configuration
// documents. It deliberately exposes only fields that are safe to replicate
// as desired state; local paths, credentials and runtime-only values stay in
// the node-local configuration.
package desiredstate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

const (
	// Version is the schema version of the management desired-state payload.
	// It is separate from the control-plane revision: revisions order documents,
	// while this value describes their wire contract.
	Version = "management.v1"

	// ProtectionPolicyKind identifies the first deliberately narrow mutation
	// slice.  More kinds must get their own typed document and validation rules;
	// callers must not turn this into a generic Config serialization shortcut.
	ProtectionPolicyKind = "protection.policy"

	// MaxPayloadBytes is a hard boundary before JSON decoding. The current
	// document is below 200 bytes; keeping the limit at 1 KiB prevents a future
	// accidental field from turning the control-plane log into an object store.
	MaxPayloadBytes = 1024
)

// ProtectionPolicySpec is the complete, non-sensitive policy snapshot for the
// protection-policy mutation. Empty values are not valid in committed desired
// state; partial HTTP patches must be merged against the live config before
// this type is constructed.
type ProtectionPolicySpec struct {
	WebAttack   string `json:"web_attack"`
	APISecurity string `json:"api_security"`
	BotCC       string `json:"bot_cc"`
	ThreatIntel string `json:"threat_intel"`
}

// ProtectionPolicyDocument is the canonical JSON document stored in the
// control-plane DesiredState payload. The explicit kind and version prevent a
// consumer from interpreting a valid document under the wrong materializer.
type ProtectionPolicyDocument struct {
	Version string               `json:"version"`
	Kind    string               `json:"kind"`
	Spec    ProtectionPolicySpec `json:"spec"`
}

// NewProtectionPolicyDocument constructs a complete document from a config
// snapshot. It does not fill defaults or silently redact values: callers must
// provide the already-merged policy, and invalid or incomplete state is
// rejected before it can be proposed to the control plane.
func NewProtectionPolicyDocument(policy config.ProtectionPolicyConfig) (ProtectionPolicyDocument, error) {
	doc := ProtectionPolicyDocument{
		Version: Version,
		Kind:    ProtectionPolicyKind,
		Spec: ProtectionPolicySpec{
			WebAttack:   policy.WebAttack,
			APISecurity: policy.APISecurity,
			BotCC:       policy.BotCC,
			ThreatIntel: policy.ThreatIntel,
		},
	}
	if err := doc.Validate(); err != nil {
		return ProtectionPolicyDocument{}, err
	}
	return doc, nil
}

// Config converts a document back into the narrow config value used by the
// protection-policy materializer. It validates again because the document
// type is exported and callers can construct or mutate it without going
// through NewProtectionPolicyDocument or DecodeProtectionPolicy.
func (d ProtectionPolicyDocument) Config() (config.ProtectionPolicyConfig, error) {
	if err := d.Validate(); err != nil {
		return config.ProtectionPolicyConfig{}, err
	}
	return config.ProtectionPolicyConfig{
		WebAttack:   d.Spec.WebAttack,
		APISecurity: d.Spec.APISecurity,
		BotCC:       d.Spec.BotCC,
		ThreatIntel: d.Spec.ThreatIntel,
	}, nil
}

// Validate checks the document identity and each enum without applying
// defaults. Full Config validation remains the materializer's responsibility
// after this policy is merged into the node-local snapshot.
func (d ProtectionPolicyDocument) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("unsupported desired-state version %q", d.Version)
	}
	if d.Kind != ProtectionPolicyKind {
		return fmt.Errorf("unsupported desired-state kind %q", d.Kind)
	}
	levels := []struct {
		name  string
		value string
	}{
		{name: "web_attack", value: d.Spec.WebAttack},
		{name: "api_security", value: d.Spec.APISecurity},
		{name: "bot_cc", value: d.Spec.BotCC},
		{name: "threat_intel", value: d.Spec.ThreatIntel},
	}
	for _, level := range levels {
		if level.value == "" {
			return fmt.Errorf("desired-state spec.%s is required", level.name)
		}
		if !config.IsProtectionLevel(level.value) {
			return fmt.Errorf("desired-state spec.%s has invalid protection level %q", level.name, level.value)
		}
	}
	return nil
}

// EncodeProtectionPolicy returns the canonical payload bytes and the digest
// bound to those exact bytes. json.Marshal on this fixed struct is stable and
// keeps the field order explicit; callers must pass both values to Proposal.
func EncodeProtectionPolicy(policy config.ProtectionPolicyConfig) ([]byte, string, error) {
	doc, err := NewProtectionPolicyDocument(policy)
	if err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("encode protection policy desired state: %w", err)
	}
	if len(payload) > MaxPayloadBytes {
		return nil, "", fmt.Errorf("desired-state payload exceeds %d bytes", MaxPayloadBytes)
	}
	return payload, controlplane.Digest(payload), nil
}

// DecodeProtectionPolicy accepts only the canonical representation emitted by
// EncodeProtectionPolicy. Rejecting alternate whitespace, field order and
// duplicate-key representations keeps the digest a single byte-level identity
// across PostgreSQL, native-raft and materializers.
func DecodeProtectionPolicy(payload []byte) (ProtectionPolicyDocument, error) {
	if len(payload) == 0 {
		return ProtectionPolicyDocument{}, fmt.Errorf("desired-state payload is empty")
	}
	if len(payload) > MaxPayloadBytes {
		return ProtectionPolicyDocument{}, fmt.Errorf("desired-state payload exceeds %d bytes", MaxPayloadBytes)
	}
	if !utf8.Valid(payload) {
		return ProtectionPolicyDocument{}, fmt.Errorf("desired-state payload is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return ProtectionPolicyDocument{}, fmt.Errorf("decode protection policy desired state: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire protectionPolicyWire
	if err := decoder.Decode(&wire); err != nil {
		return ProtectionPolicyDocument{}, fmt.Errorf("decode protection policy desired state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ProtectionPolicyDocument{}, fmt.Errorf("desired-state payload must contain exactly one JSON document")
		}
		return ProtectionPolicyDocument{}, fmt.Errorf("decode trailing desired-state JSON: %w", err)
	}
	if wire.Spec == nil {
		return ProtectionPolicyDocument{}, fmt.Errorf("desired-state spec is required")
	}
	doc := ProtectionPolicyDocument{
		Version: wire.Version,
		Kind:    wire.Kind,
		Spec: ProtectionPolicySpec{
			WebAttack:   requiredString(wire.Spec.WebAttack),
			APISecurity: requiredString(wire.Spec.APISecurity),
			BotCC:       requiredString(wire.Spec.BotCC),
			ThreatIntel: requiredString(wire.Spec.ThreatIntel),
		},
	}
	if err := doc.Validate(); err != nil {
		return ProtectionPolicyDocument{}, err
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return ProtectionPolicyDocument{}, fmt.Errorf("canonicalize protection policy desired state: %w", err)
	}
	if !bytes.Equal(canonical, payload) {
		return ProtectionPolicyDocument{}, fmt.Errorf("desired-state payload is not canonical JSON")
	}
	return doc, nil
}

// DecodeProtectionPolicyConfig is a convenience for a materializer that has
// already verified the control-plane digest and fence.
func DecodeProtectionPolicyConfig(payload []byte) (config.ProtectionPolicyConfig, error) {
	doc, err := DecodeProtectionPolicy(payload)
	if err != nil {
		return config.ProtectionPolicyConfig{}, err
	}
	return doc.Config()
}

// NewProtectionPolicyProposal creates the only proposal shape this package
// permits for the protection-policy document. The outer control-plane version,
// inner document version, payload bytes and digest are derived together so a
// caller cannot accidentally bind a management.v2 envelope to a v1 payload.
// StateMachine still owns epoch/revision/leader fencing when it applies it.
func NewProtectionPolicyProposal(policy config.ProtectionPolicyConfig, leaderID string, expectedEpoch controlplane.Epoch, expectedRevision controlplane.Revision, nonce string) (controlplane.Proposal, error) {
	if !controlplane.ValidIdentity(leaderID) || !controlplane.ValidIdentity(nonce) {
		return controlplane.Proposal{}, fmt.Errorf("protection policy proposal requires strict leader and nonce identities")
	}
	payload, digest, err := EncodeProtectionPolicy(policy)
	if err != nil {
		return controlplane.Proposal{}, err
	}
	return controlplane.Proposal{
		LeaderID:         leaderID,
		ExpectedEpoch:    expectedEpoch,
		ExpectedRevision: expectedRevision,
		Version:          Version,
		Payload:          payload,
		Digest:           digest,
		Nonce:            nonce,
	}, nil
}

// ValidateProtectionPolicyProposal binds the outer proposal metadata to the
// canonical typed payload. It intentionally does not validate leader/epoch/
// revision fencing; that remains the StateMachine/Coordinator boundary.
func ValidateProtectionPolicyProposal(proposal controlplane.Proposal) error {
	if proposal.Version != Version {
		return fmt.Errorf("protection policy proposal has unsupported version %q", proposal.Version)
	}
	if proposal.Digest == "" || proposal.Digest != controlplane.Digest(proposal.Payload) {
		return fmt.Errorf("protection policy proposal digest does not match payload")
	}
	doc, err := DecodeProtectionPolicy(proposal.Payload)
	if err != nil {
		return fmt.Errorf("validate protection policy proposal payload: %w", err)
	}
	if doc.Version != proposal.Version {
		return fmt.Errorf("protection policy proposal outer and inner versions differ")
	}
	return nil
}

// MaterializeProtectionPolicy builds a candidate node-local configuration from
// a committed typed payload. It never mutates local and never serializes the
// full Config into the control plane. The caller must validate the commit's
// fence and exact digest before invoking this function.
func MaterializeProtectionPolicy(local *config.Config, payload []byte) (*config.Config, error) {
	doc, err := DecodeProtectionPolicy(payload)
	if err != nil {
		return nil, err
	}
	policy, err := doc.Config()
	if err != nil {
		return nil, err
	}
	candidate, err := config.Clone(local)
	if err != nil {
		return nil, fmt.Errorf("clone local config for protection policy: %w", err)
	}
	candidate.Protection.Policy = policy
	if err := config.Validate(candidate); err != nil {
		return nil, fmt.Errorf("validate materialized protection policy config: %w", err)
	}
	return candidate, nil
}

// MaterializeProtectionPolicyProposal combines the typed proposal boundary
// with candidate construction. Fencing remains the caller's responsibility;
// this helper only prevents an untyped or digest-mismatched payload from being
// applied to a local snapshot.
func MaterializeProtectionPolicyProposal(local *config.Config, proposal controlplane.Proposal) (*config.Config, error) {
	if err := ValidateProtectionPolicyProposal(proposal); err != nil {
		return nil, err
	}
	return MaterializeProtectionPolicy(local, proposal.Payload)
}

type protectionPolicyWire struct {
	Version string                    `json:"version"`
	Kind    string                    `json:"kind"`
	Spec    *protectionPolicySpecWire `json:"spec"`
}

type protectionPolicySpecWire struct {
	WebAttack   *string `json:"web_attack"`
	APISecurity *string `json:"api_security"`
	BotCC       *string `json:"bot_cc"`
	ThreatIntel *string `json:"threat_intel"`
}

func requiredString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// rejectDuplicateJSONKeys walks the first JSON value and rejects duplicate
// object members before decoding into a Go struct. encoding/json otherwise
// accepts a later member as an overwrite, which would allow two different
// byte payloads to describe the same desired state and undermine digest
// identity.
func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("malformed JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}
