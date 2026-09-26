package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

type crpFenceConsensusFake struct {
	state        controlplane.State
	currentErr   error
	establishErr error
}

func (f *crpFenceConsensusFake) Backend() string                                    { return controlplane.ConsensusBackendNativeRaft }
func (f *crpFenceConsensusFake) Prepare(context.Context) error                      { return nil }
func (f *crpFenceConsensusFake) Health(context.Context) error                       { return nil }
func (f *crpFenceConsensusFake) Propose(context.Context, controlplane.Commit) error { return nil }
func (f *crpFenceConsensusFake) Close() error                                       { return nil }
func (f *crpFenceConsensusFake) Machine() *controlplane.StateMachine                { return nil }

func (f *crpFenceConsensusFake) Current(ctx context.Context, clusterID string) (controlplane.State, error) {
	if err := ctx.Err(); err != nil {
		return controlplane.State{}, err
	}
	if f.currentErr != nil {
		return controlplane.State{}, f.currentErr
	}
	if clusterID != f.state.ClusterID {
		return controlplane.State{}, controlplane.ErrStateNotFound
	}
	return cloneCRPFenceState(f.state), nil
}

func (f *crpFenceConsensusFake) Establish(ctx context.Context, state controlplane.State) (controlplane.FenceToken, error) {
	if err := ctx.Err(); err != nil {
		return controlplane.FenceToken{}, err
	}
	if f.establishErr != nil {
		return controlplane.FenceToken{}, f.establishErr
	}
	if state.ClusterID != f.state.ClusterID || state.LeaderID != f.state.LeaderID || state.Epoch != f.state.Epoch || state.Revision != f.state.Revision || state.Desired.Digest != f.state.Desired.Digest {
		return controlplane.FenceToken{}, controlplane.ErrStaleFence
	}
	nonce := ""
	for candidate, revision := range state.NonceLedger {
		if revision == state.Revision {
			nonce = candidate
			break
		}
	}
	if nonce == "" {
		return controlplane.FenceToken{}, controlplane.ErrStaleFence
	}
	return controlplane.FenceToken{ClusterID: state.ClusterID, LeaderID: state.LeaderID, Epoch: state.Epoch, Revision: state.Revision, Digest: state.Desired.Digest, Nonce: nonce}, nil
}

func cloneCRPFenceState(in controlplane.State) controlplane.State {
	out := in
	out.Desired.Payload = append([]byte(nil), in.Desired.Payload...)
	out.NonceLedger = make(map[string]controlplane.Revision, len(in.NonceLedger))
	for nonce, revision := range in.NonceLedger {
		out.NonceLedger[nonce] = revision
	}
	return out
}

func crpFenceState() controlplane.State {
	payload := []byte(`{"policy":"baseline"}`)
	return controlplane.State{
		ClusterID: "cluster-a",
		LeaderID:  "leader-a",
		Term:      3,
		Epoch:     7,
		Revision:  11,
		Desired:   controlplane.DesiredState{Version: "v11", Digest: controlplane.Digest(payload), Payload: payload},
		NonceLedger: map[string]controlplane.Revision{
			"nonce-11": 11,
		},
	}
}

func crpFenceRequest() activation.AuthorizationRequest {
	return activation.AuthorizationRequest{Identity: activation.TransportIdentity{ClusterID: "cluster-a", NodeID: "node-a", Role: "waf"}}
}

func TestProductionCRPFenceTokenBindsEveryNativeRaftField(t *testing.T) {
	base := controlplane.FenceToken{ClusterID: "cluster-a", LeaderID: "leader-a", Epoch: 7, Revision: 11, Digest: controlplane.Digest([]byte("baseline")), Nonce: "nonce-11"}
	if got, want := productionCRPFenceToken(base), productionCRPFenceToken(base); got != want {
		t.Fatalf("token is not stable: got %q want %q", got, want)
	}
	for name, mutate := range map[string]func(*controlplane.FenceToken){
		"leader":   func(token *controlplane.FenceToken) { token.LeaderID = "leader-b" },
		"epoch":    func(token *controlplane.FenceToken) { token.Epoch++ },
		"revision": func(token *controlplane.FenceToken) { token.Revision++ },
		"digest":   func(token *controlplane.FenceToken) { token.Digest = controlplane.Digest([]byte("changed")) },
		"nonce":    func(token *controlplane.FenceToken) { token.Nonce = "nonce-12" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if productionCRPFenceToken(changed) == productionCRPFenceToken(base) {
				t.Fatalf("%s drift retained the old CRP token", name)
			}
		})
	}
}

func TestProductionCRPFenceSourceRejectsDriftAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	consensus := &crpFenceConsensusFake{state: crpFenceState()}
	source, err := NewProductionCRPFenceSource(consensus)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	request := crpFenceRequest()
	fence, err := source.CurrentFence(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	authorization := activation.Authorization{Request: request, Fence: fence}
	if err := source.ValidateFence(context.Background(), authorization, fence); err != nil {
		t.Fatalf("current fence rejected: %v", err)
	}

	for name, mutate := range map[string]func(*controlplane.State){
		"leader": func(state *controlplane.State) { state.LeaderID = "leader-b" },
		"epoch":  func(state *controlplane.State) { state.Epoch++ },
		"revision": func(state *controlplane.State) {
			state.Revision++
			state.NonceLedger = map[string]controlplane.Revision{"nonce-12": state.Revision}
		},
		"digest": func(state *controlplane.State) { state.Desired.Digest = controlplane.Digest([]byte("changed")) },
		"nonce": func(state *controlplane.State) {
			state.NonceLedger = map[string]controlplane.Revision{"nonce-next": state.Revision}
		},
	} {
		t.Run(name, func(t *testing.T) {
			consensus.state = crpFenceState()
			mutate(&consensus.state)
			if err := source.ValidateFence(context.Background(), authorization, fence); !errors.Is(err, activation.ErrStaleFence) {
				t.Fatalf("ValidateFence() error=%v, want ErrStaleFence", err)
			}
		})
	}

	expired := authorization
	expired.Fence.ExpiresAt = now
	if err := source.ValidateFence(context.Background(), expired, expired.Fence); !errors.Is(err, activation.ErrFenceExpired) {
		t.Fatalf("expired fence error=%v, want ErrFenceExpired", err)
	}
}

func TestProductionCRPFenceSourceFailsClosedWhenConsensusIsUnavailable(t *testing.T) {
	if _, err := NewProductionCRPFenceSource(nil); !errors.Is(err, activation.ErrControlPlaneUnavailable) {
		t.Fatalf("nil consensus error=%v, want ErrControlPlaneUnavailable", err)
	}
	consensus := &crpFenceConsensusFake{state: crpFenceState(), currentErr: errors.New("raft unavailable")}
	source, err := NewProductionCRPFenceSource(consensus)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.CurrentFence(context.Background(), crpFenceRequest()); !errors.Is(err, activation.ErrControlPlaneUnavailable) {
		t.Fatalf("CurrentFence() error=%v, want ErrControlPlaneUnavailable", err)
	}
}
