// Package materializer contains the node-local durability boundary for
// control-plane desired state. It deliberately has no HTTP, database,
// consensus, or runtime side effects.
package materializer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

const (
	ReceiptSchema = "materializer.v2"

	PhasePrepared            Phase = "prepared"
	PhaseBaselinePersisted   Phase = "baseline_persisted"
	PhaseYAMLPersisted       Phase = "yaml_persisted"
	PhaseRuntimeIntent       Phase = "runtime_intent"
	PhaseRuntimeApplied      Phase = "runtime_applied"
	PhaseCompensationPending Phase = "compensation_pending"
	PhaseApplied             Phase = "applied"

	// MaxReceiptBytes is deliberately larger than the typed desired-state
	// payload limit while remaining a small bounded journal record.
	MaxReceiptBytes = 64 << 10
)

var (
	ErrReceiptNotFound  = errors.New("materializer receipt not found")
	ErrReceiptCorrupt   = errors.New("materializer receipt is corrupt")
	ErrReceiptUnsafe    = errors.New("materializer receipt path is unsafe")
	ErrReceiptAmbiguous = errors.New("materializer primary and backup receipts disagree")
	ErrCommitConflict   = errors.New("materializer commit conflicts with existing receipt")
	ErrStaleEpoch       = errors.New("materializer commit epoch is stale")
	ErrStaleRevision    = errors.New("materializer commit revision is stale")
	ErrPhaseRegression  = errors.New("materializer receipt phase regresses")
	ErrInvalidPhase     = errors.New("materializer receipt phase is invalid")
)

// Phase is the local materialization lifecycle. It is not a control-plane
// state and must never be used to roll back a consensus commit.
type Phase string

// CommitIdentity contains only non-sensitive exact commit metadata. Payload is
// kept on Receipt so callers cannot accidentally serialize a whole Config.
type CommitIdentity struct {
	ClusterID string                `json:"cluster_id"`
	LeaderID  string                `json:"leader_id"`
	Epoch     controlplane.Epoch    `json:"epoch"`
	Revision  controlplane.Revision `json:"revision"`
	Version   string                `json:"version"`
	Digest    string                `json:"digest"`
	Nonce     string                `json:"nonce"`
}

// Receipt is the complete durable journal/LKG record. Payload is the exact
// canonical management.v1/protection.policy bytes, never a generic Config.
type Receipt struct {
	Schema  string         `json:"schema"`
	Phase   Phase          `json:"phase"`
	Commit  CommitIdentity `json:"commit"`
	Payload []byte         `json:"payload"`
}

// NewReceipt derives a receipt from the exact committed event and binds the
// digest to the exact payload bytes.
func NewReceipt(commit controlplane.Commit, phase Phase) (Receipt, error) {
	if !validPhase(phase) {
		return Receipt{}, ErrInvalidPhase
	}
	if commit.State.ClusterID != commit.Fence.ClusterID || commit.State.LeaderID != commit.Fence.LeaderID || commit.State.Epoch != commit.Fence.Epoch || commit.State.Revision != commit.Fence.Revision || commit.State.Desired.Version == "" || commit.State.Desired.Digest != commit.Fence.Digest || commit.State.Desired.Digest != controlplane.Digest(commit.State.Desired.Payload) || commit.Fence.Nonce == "" {
		return Receipt{}, fmt.Errorf("%w: commit metadata is not exact", ErrReceiptCorrupt)
	}
	r := Receipt{
		Schema: ReceiptSchema,
		Phase:  phase,
		Commit: CommitIdentity{
			ClusterID: commit.Fence.ClusterID,
			LeaderID:  commit.Fence.LeaderID,
			Epoch:     commit.Fence.Epoch,
			Revision:  commit.Fence.Revision,
			Version:   commit.State.Desired.Version,
			Digest:    commit.Fence.Digest,
			Nonce:     commit.Fence.Nonce,
		},
		Payload: append([]byte(nil), commit.State.Desired.Payload...),
	}
	if err := r.Validate(); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

func (r Receipt) Clone() Receipt {
	r.Payload = append([]byte(nil), r.Payload...)
	return r
}

func (r Receipt) Validate() error {
	if r.Schema != ReceiptSchema {
		return fmt.Errorf("%w: unsupported schema %q", ErrReceiptCorrupt, r.Schema)
	}
	if !validPhase(r.Phase) {
		return fmt.Errorf("%w: %q", ErrInvalidPhase, r.Phase)
	}
	if !controlplane.ValidIdentity(r.Commit.ClusterID) || !controlplane.ValidIdentity(r.Commit.LeaderID) || !controlplane.ValidIdentity(r.Commit.Version) || !controlplane.ValidIdentity(r.Commit.Nonce) {
		return fmt.Errorf("%w: commit identities are invalid", ErrReceiptCorrupt)
	}
	if r.Commit.Epoch == 0 || r.Commit.Revision == 0 || r.Commit.Digest == "" || len(r.Payload) == 0 || len(r.Payload) > desiredstate.MaxPayloadBytes || !utf8.Valid(r.Payload) {
		return fmt.Errorf("%w: commit fence or payload is invalid", ErrReceiptCorrupt)
	}
	if r.Commit.Digest != controlplane.Digest(r.Payload) {
		return fmt.Errorf("%w: payload digest does not match commit", ErrReceiptCorrupt)
	}
	if r.Commit.Version != desiredstate.Version {
		return fmt.Errorf("%w: unsupported desired-state version %q", ErrReceiptCorrupt, r.Commit.Version)
	}
	if _, err := desiredstate.DecodeProtectionPolicy(r.Payload); err != nil {
		return fmt.Errorf("%w: desired-state payload: %v", ErrReceiptCorrupt, err)
	}
	return nil
}

// FromCommit validates the exact commit contract before a caller can journal
// it. This is intentionally narrower than StateMachine.ValidateFence: a
// materializer tracks its own current LKG and does not accept historical
// revisions merely because the state machine still remembers their fence.
func FromCommit(commit controlplane.Commit, phase Phase) (Receipt, error) {
	return NewReceipt(commit, phase)
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhasePrepared, PhaseBaselinePersisted, PhaseYAMLPersisted, PhaseRuntimeIntent, PhaseRuntimeApplied, PhaseCompensationPending, PhaseApplied:
		return true
	default:
		return false
	}
}

func sameCommit(a, b Receipt) bool {
	return a.Schema == b.Schema && a.Commit == b.Commit && bytes.Equal(a.Payload, b.Payload)
}

// ValidateTransition checks a local materializer transition. Equal commit
// metadata is idempotent only when its phase does not regress. A newer epoch
// may reset revision ordering; within an epoch every lower revision is stale.
func ValidateTransition(previous *Receipt, next Receipt) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if previous == nil {
		if next.Phase != PhasePrepared {
			return fmt.Errorf("%w: first receipt must be prepared", ErrPhaseRegression)
		}
		return nil
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	if next.Commit.ClusterID != previous.Commit.ClusterID {
		return fmt.Errorf("%w: cluster changed", ErrCommitConflict)
	}
	if next.Commit.Epoch < previous.Commit.Epoch {
		return ErrStaleEpoch
	}
	if next.Commit.Epoch == previous.Commit.Epoch && next.Commit.LeaderID != previous.Commit.LeaderID {
		return fmt.Errorf("%w: leader changed within epoch", ErrCommitConflict)
	}
	if next.Commit.Epoch == previous.Commit.Epoch && next.Commit.Revision < previous.Commit.Revision {
		return ErrStaleRevision
	}
	if next.Commit.Epoch == previous.Commit.Epoch && next.Commit.Revision == previous.Commit.Revision {
		if !sameCommit(*previous, next) {
			return ErrCommitConflict
		}
		if next.Phase == previous.Phase {
			return nil
		}
		if previous.Phase != PhaseApplied && next.Phase == PhaseCompensationPending {
			return nil
		}
		switch previous.Phase {
		case PhasePrepared:
			if next.Phase == PhaseBaselinePersisted {
				return nil
			}
		case PhaseCompensationPending:
			if next.Phase == PhaseRuntimeIntent {
				return nil
			}
		case PhaseBaselinePersisted:
			if next.Phase == PhaseYAMLPersisted {
				return nil
			}
		case PhaseYAMLPersisted:
			if next.Phase == PhaseRuntimeIntent {
				return nil
			}
		case PhaseRuntimeIntent:
			if next.Phase == PhaseRuntimeApplied || next.Phase == PhaseYAMLPersisted {
				return nil
			}
		case PhaseRuntimeApplied:
			if next.Phase == PhaseApplied {
				return nil
			}
		}
		return ErrPhaseRegression
	}
	if next.Phase != PhasePrepared {
		return fmt.Errorf("%w: a new commit must start prepared", ErrPhaseRegression)
	}
	return nil
}

// Compare returns whether next is an exact idempotent replay, after checking
// the same safety rules as ValidateTransition.
func Compare(previous *Receipt, next Receipt) (idempotent bool, err error) {
	if err := ValidateTransition(previous, next); err != nil {
		return false, err
	}
	return previous != nil && sameCommit(*previous, next) && previous.Phase == next.Phase, nil
}

func encodeReceipt(r Receipt) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode materializer receipt: %w", err)
	}
	if len(b) > MaxReceiptBytes {
		return nil, fmt.Errorf("%w: receipt exceeds %d bytes", ErrReceiptCorrupt, MaxReceiptBytes)
	}
	return b, nil
}

func decodeReceipt(data []byte) (Receipt, error) {
	if len(data) == 0 || len(data) > MaxReceiptBytes {
		return Receipt{}, fmt.Errorf("%w: receipt size is invalid", ErrReceiptCorrupt)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var r Receipt
	if err := decoder.Decode(&r); err != nil {
		return Receipt{}, fmt.Errorf("%w: decode receipt: %v", ErrReceiptCorrupt, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Receipt{}, fmt.Errorf("%w: trailing JSON", ErrReceiptCorrupt)
		}
		return Receipt{}, fmt.Errorf("%w: trailing JSON: %v", ErrReceiptCorrupt, err)
	}
	canonical, err := encodeReceipt(r)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(canonical, data) {
		return Receipt{}, fmt.Errorf("%w: receipt is not canonical JSON", ErrReceiptCorrupt)
	}
	return r, nil
}
