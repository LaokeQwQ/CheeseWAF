package desiredstate

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

type coordinatorTestConsensus struct {
	state     controlplane.State
	proposals []controlplane.Commit
}

func (s *coordinatorTestConsensus) Current(context.Context, string) (controlplane.State, error) {
	return s.state, nil
}

func (s *coordinatorTestConsensus) Propose(_ context.Context, commit controlplane.Commit) error {
	s.proposals = append(s.proposals, commit)
	s.state = commit.State
	return nil
}

type coordinatorTestDurable struct {
	state   controlplane.State
	commits []controlplane.Commit
	err     error
}

type countingProtectionPolicyMutator struct {
	inner ProtectionPolicyMutator
	calls int
}

func (m *countingProtectionPolicyMutator) Prepare(current config.ProtectionPolicyConfig, request ProtectionPolicyMutationRequest) (ProtectionPolicyMutation, error) {
	m.calls++
	return m.inner.Prepare(current, request)
}

func (s *coordinatorTestDurable) LoadState(context.Context, string) (controlplane.State, error) {
	return s.state, nil
}

func (s *coordinatorTestDurable) AppendCommit(_ context.Context, commit controlplane.Commit) error {
	if s.err != nil {
		return s.err
	}
	s.commits = append(s.commits, commit)
	s.state = commit.State
	return nil
}

func newProtectionPolicyCoordinatorTestService(t *testing.T, durable *coordinatorTestDurable) (*ProtectionPolicyCoordinatorService, *controlplane.StateMachine, *coordinatorTestConsensus) {
	t.Helper()
	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	consensus := &coordinatorTestConsensus{state: machine.Snapshot()}
	if durable == nil {
		durable = &coordinatorTestDurable{state: machine.Snapshot()}
	}
	coordinator, err := controlplane.NewCoordinator(machine, consensus, durable)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewProtectionPolicyCoordinatorService(NewProtectionPolicyMutationService(), coordinator)
	if err != nil {
		t.Fatal(err)
	}
	return service, machine, consensus
}

func coordinatorMutationRequest() ProtectionPolicyMutationRequest {
	return ProtectionPolicyMutationRequest{
		Actor:            "operator-only-audit",
		LeaderID:         "node-a",
		ExpectedEpoch:    1,
		ExpectedRevision: 0,
		Nonce:            "policy-change-1",
		Patch: ProtectionPolicyPatch{
			WebAttack: stringPointer(config.ProtectionLevelHigh),
		},
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestProtectionPolicyCoordinatorRequiresInjectedDependencies(t *testing.T) {
	if _, err := NewProtectionPolicyCoordinatorService(nil, nil); !errors.Is(err, ErrProtectionPolicyCoordinatorUnavailable) {
		t.Fatalf("constructor error = %v, want %v", err, ErrProtectionPolicyCoordinatorUnavailable)
	}
	var service *ProtectionPolicyCoordinatorService
	if _, err := service.ProposeAndApply(context.Background(), config.DefaultProtectionPolicy(), coordinatorMutationRequest()); !errors.Is(err, ErrProtectionPolicyCoordinatorUnavailable) {
		t.Fatalf("nil receiver error = %v, want %v", err, ErrProtectionPolicyCoordinatorUnavailable)
	}
	if err := (&ProtectionPolicyCoordinatorService{}).Apply(context.Background(), controlplane.Commit{}); !errors.Is(err, ErrProtectionPolicyCoordinatorUnavailable) {
		t.Fatalf("zero-value Apply error = %v, want %v", err, ErrProtectionPolicyCoordinatorUnavailable)
	}
}

func TestProtectionPolicyCoordinatorPreparesThenCommitsWithoutReplicatingActor(t *testing.T) {
	service, machine, consensus := newProtectionPolicyCoordinatorTestService(t, nil)
	current := config.DefaultProtectionPolicy()
	request := coordinatorMutationRequest()
	result, err := service.ProposeAndApply(context.Background(), current, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mutation.Actor != request.Actor {
		t.Fatalf("audit actor = %q, want %q", result.Mutation.Actor, request.Actor)
	}
	if result.Commit.State.Revision != 1 || result.Commit.Fence.Revision != 1 {
		t.Fatalf("commit = %+v, want revision 1", result.Commit)
	}
	if result.Mutation.After.WebAttack != config.ProtectionLevelHigh {
		t.Fatalf("merged policy = %+v, want web_attack=high", result.Mutation.After)
	}
	if bytes.Contains(result.Commit.State.Desired.Payload, []byte(request.Actor)) {
		t.Fatalf("actor was replicated in desired-state payload: %s", result.Commit.State.Desired.Payload)
	}
	decoded, err := DecodeProtectionPolicyConfig(result.Commit.State.Desired.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != result.Mutation.After {
		t.Fatalf("committed policy = %+v, want prepared policy %+v", decoded, result.Mutation.After)
	}
	if got := machine.Snapshot(); got.Revision != 1 || got.WriteFrozen {
		t.Fatalf("machine snapshot = %+v, want committed unfrozen revision 1", got)
	}
	if len(consensus.proposals) != 1 {
		t.Fatalf("consensus proposals = %d, want 1", len(consensus.proposals))
	}
}

func TestProtectionPolicyCoordinatorReturnsExactCommitForDurableRetry(t *testing.T) {
	durableErr := errors.New("postgres unavailable")
	durable := &coordinatorTestDurable{err: durableErr}
	service, machine, consensus := newProtectionPolicyCoordinatorTestService(t, durable)
	countingMutator := &countingProtectionPolicyMutator{inner: service.mutator}
	service.mutator = countingMutator
	request := coordinatorMutationRequest()
	result, err := service.ProposeAndApply(context.Background(), config.DefaultProtectionPolicy(), request)
	if err == nil || !errors.Is(err, durableErr) {
		t.Fatalf("durable error = %v, want wrapped %v", err, durableErr)
	}
	if result.Commit.State.Revision != 1 || result.Commit.Fence.Nonce != request.Nonce {
		t.Fatalf("failed result commit = %+v, want exact revision/nonce", result.Commit)
	}
	if got := machine.Snapshot(); got.Revision != 0 || !got.WriteFrozen {
		t.Fatalf("failed persistence exposed state: %+v", got)
	}
	durable.err = nil
	if err := service.Apply(context.Background(), result.Commit); err != nil {
		t.Fatalf("exact commit retry failed: %v", err)
	}
	if countingMutator.calls != 1 {
		t.Fatalf("exact commit retry called Prepare %d times, want 1", countingMutator.calls)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("retry duplicated side effects: consensus=%d durable=%d", len(consensus.proposals), len(durable.commits))
	}
	if got := machine.Snapshot(); got.Revision != 1 || !got.WriteFrozen {
		t.Fatalf("retry did not preserve fail-closed state after commit installation: %+v", got)
	}
}

func TestProtectionPolicyCoordinatorDoesNotSubmitWhenPreparationFails(t *testing.T) {
	service, _, consensus := newProtectionPolicyCoordinatorTestService(t, nil)
	request := coordinatorMutationRequest()
	request.Patch.WebAttack = stringPointer("invalid-level")
	if _, err := service.ProposeAndApply(context.Background(), config.DefaultProtectionPolicy(), request); err == nil {
		t.Fatal("invalid mutation unexpectedly succeeded")
	}
	if len(consensus.proposals) != 0 {
		t.Fatalf("preparation failure reached consensus: %d proposals", len(consensus.proposals))
	}
}
