package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

const productionCRPFenceTTL = 30 * time.Second

// ProductionCRPFenceSource projects the exact live native-raft fence into the
// CRP activation contract. The token is a deterministic digest of every
// native-raft fencing field, rather than a locally minted capability.
//
// CurrentFence requires the local consensus dependency to establish the
// current fence. A follower, unavailable raft runtime, or inconsistent
// snapshot therefore fails closed instead of issuing a CRP authorization.
type ProductionCRPFenceSource struct {
	consensus ProductionConsensusDependency
	now       func() time.Time
}

func NewProductionCRPFenceSource(consensus ProductionConsensusDependency) (*ProductionCRPFenceSource, error) {
	if isNilProductionDependency(consensus) {
		return nil, fmt.Errorf("%w: native-raft consensus is required", activation.ErrControlPlaneUnavailable)
	}
	return &ProductionCRPFenceSource{consensus: consensus, now: time.Now}, nil
}

func (s *ProductionCRPFenceSource) CurrentFence(ctx context.Context, request activation.AuthorizationRequest) (activation.Fence, error) {
	if s == nil || isNilProductionDependency(s.consensus) || s.now == nil || !controlplane.ValidIdentity(request.Identity.ClusterID) {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	if ctx == nil {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	state, err := s.consensus.Current(ctx, request.Identity.ClusterID)
	if err != nil {
		return activation.Fence{}, fmt.Errorf("%w: current native-raft state: %v", activation.ErrControlPlaneUnavailable, err)
	}
	if state.ClusterID != request.Identity.ClusterID {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	token, err := s.consensus.Establish(ctx, state)
	if err != nil {
		return activation.Fence{}, fmt.Errorf("%w: establish native-raft fence: %v", activation.ErrControlPlaneUnavailable, err)
	}
	if !validProductionCRPFenceToken(state, token) {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	return activation.Fence{
		ClusterID: token.ClusterID,
		Token:     productionCRPFenceToken(token),
		Epoch:     uint64(token.Epoch),
		Revision:  uint64(token.Revision),
		ExpiresAt: s.now().UTC().Add(productionCRPFenceTTL),
	}, nil
}

// ValidateFence deliberately obtains a second current fence. CurrentFence is
// called immediately before this method by the durable store, while this
// second read detects a leader, epoch, revision, digest, or nonce transition
// that races that first read. The caller must not retain a PostgreSQL
// transaction or row lock while calling this method.
func (s *ProductionCRPFenceSource) ValidateFence(ctx context.Context, authorization activation.Authorization, observed activation.Fence) error {
	if s == nil || s.now == nil {
		return activation.ErrControlPlaneUnavailable
	}
	if !authorization.Fence.ExpiresAt.After(s.now().UTC()) {
		return activation.ErrFenceExpired
	}
	if !sameProductionCRPFence(authorization.Fence, observed) {
		return activation.ErrStaleFence
	}
	fresh, err := s.CurrentFence(ctx, authorization.Request)
	if err != nil {
		return err
	}
	if !sameProductionCRPFence(authorization.Fence, fresh) {
		return activation.ErrStaleFence
	}
	return nil
}

func validProductionCRPFenceToken(state controlplane.State, token controlplane.FenceToken) bool {
	return controlplane.ValidIdentity(token.ClusterID) && token.ClusterID == state.ClusterID &&
		controlplane.ValidIdentity(token.LeaderID) && token.LeaderID == state.LeaderID &&
		token.Epoch != 0 && token.Epoch == state.Epoch && token.Revision != 0 && token.Revision == state.Revision &&
		token.Digest != "" && token.Digest == state.Desired.Digest && controlplane.ValidIdentity(token.Nonce) &&
		state.NonceLedger[token.Nonce] == token.Revision
}

func sameProductionCRPFence(left, right activation.Fence) bool {
	return left.ClusterID == right.ClusterID && left.Token == right.Token && left.Epoch == right.Epoch && left.Revision == right.Revision
}

func productionCRPFenceToken(token controlplane.FenceToken) string {
	// Length-prefixing avoids ambiguous concatenations such as ("ab", "c")
	// and ("a", "bc") producing the same representation.
	payload := fmt.Sprintf("crp-native-raft-fence-v1\x00%d:%s\x00%d:%s\x00%d\x00%d\x00%d:%s\x00%d:%s",
		len(token.ClusterID), token.ClusterID,
		len(token.LeaderID), token.LeaderID,
		token.Epoch,
		token.Revision,
		len(token.Digest), token.Digest,
		len(token.Nonce), token.Nonce,
	)
	sum := sha256.Sum256([]byte(payload))
	return "crp-raft-" + hex.EncodeToString(sum[:])
}

var _ interface {
	CurrentFence(context.Context, activation.AuthorizationRequest) (activation.Fence, error)
	ValidateFence(context.Context, activation.Authorization, activation.Fence) error
} = (*ProductionCRPFenceSource)(nil)
