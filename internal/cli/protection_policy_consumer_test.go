package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

type policyConsumerConsensus struct {
	state controlplane.State
}

func (s *policyConsumerConsensus) Current(context.Context, string) (controlplane.State, error) {
	return s.state, nil
}

func (s *policyConsumerConsensus) Propose(_ context.Context, commit controlplane.Commit) error {
	s.state = commit.State
	return nil
}

type policyConsumerDurable struct {
	state    controlplane.State
	onAppend func()
}

func (s *policyConsumerDurable) LoadState(context.Context, string) (controlplane.State, error) {
	return s.state, nil
}

func (s *policyConsumerDurable) AppendCommit(_ context.Context, commit controlplane.Commit) error {
	s.state = commit.State
	if s.onAppend != nil {
		s.onAppend()
	}
	return nil
}

type policyConsumerMaterializer struct {
	err         error
	calls       int
	commit      controlplane.Commit
	contextErr  error
	hasDeadline bool
}

func (m *policyConsumerMaterializer) ApplyCommitted(ctx context.Context, commit controlplane.Commit) error {
	m.calls++
	m.commit = commit
	m.contextErr = ctx.Err()
	_, m.hasDeadline = ctx.Deadline()
	return m.err
}

func newPolicyConsumerFixture(t *testing.T) (*protectionPolicyCoordinatorConsumer, *controlplane.StateMachine, *policyConsumerMaterializer, *policyConsumerDurable) {
	t.Helper()
	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.InstallLeadership(1, "leader-a"); err != nil {
		t.Fatal(err)
	}
	consensus := &policyConsumerConsensus{state: machine.Snapshot()}
	durable := &policyConsumerDurable{state: machine.Snapshot()}
	coordinator, err := controlplane.NewCoordinator(machine, consensus, durable)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	h := handler.New(handler.Options{Config: &cfg})
	applier := &policyConsumerMaterializer{}
	consumer, err := newProtectionPolicyCoordinatorConsumer(h, machine, coordinator, applier)
	if err != nil {
		t.Fatal(err)
	}
	return consumer, machine, applier, durable
}

func TestProtectionPolicyConsumerInvalidPatchDoesNotFreezeHealthyGeneration(t *testing.T) {
	consumer, machine, applier, _ := newPolicyConsumerFixture(t)
	invalid := "maximum"
	if _, err := consumer.ProposeAndApply(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &invalid}); !errors.Is(err, desiredstate.ErrProtectionPolicyMutationInvalid) {
		t.Fatalf("invalid patch error=%v, want ErrProtectionPolicyMutationInvalid", err)
	}
	if consumer.failed != nil {
		t.Fatalf("invalid patch permanently failed consumer: %v", consumer.failed)
	}
	if state := machine.Snapshot(); state.WriteFrozen || state.Revision != 0 {
		t.Fatalf("invalid patch changed healthy generation: %+v", state)
	}

	strict := config.ProtectionLevelStrict
	result, err := consumer.ProposeAndApply(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("valid request after invalid patch: %v", err)
	}
	if result.Commit.State.Revision != 1 || applier.calls != 1 {
		t.Fatalf("valid request commit=%+v materializer calls=%d", result.Commit, applier.calls)
	}
}

func TestProtectionPolicyConsumerPreCanceledRequestDoesNotFreezeHealthyGeneration(t *testing.T) {
	consumer, machine, applier, _ := newPolicyConsumerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	strict := config.ProtectionLevelStrict
	if _, err := consumer.ProposeAndApply(ctx, "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled request error=%v, want context.Canceled", err)
	}
	if consumer.failed != nil {
		t.Fatalf("pre-canceled request permanently failed consumer: %v", consumer.failed)
	}
	if state := machine.Snapshot(); state.WriteFrozen || state.Revision != 0 {
		t.Fatalf("pre-canceled request changed healthy generation: %+v", state)
	}
	if applier.calls != 0 {
		t.Fatalf("pre-canceled request reached materializer %d times", applier.calls)
	}
}

func TestProtectionPolicyConsumerFreezesAfterCommittedMaterializationFailure(t *testing.T) {
	consumer, machine, applier, _ := newPolicyConsumerFixture(t)
	wantErr := errors.New("runtime apply failed")
	applier.err = wantErr
	strict := config.ProtectionLevelStrict
	result, err := consumer.ProposeAndApply(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if !errors.Is(err, wantErr) {
		t.Fatalf("materialization error=%v, want %v", err, wantErr)
	}
	if result.Commit.State.Revision != 1 || applier.calls != 1 {
		t.Fatalf("failed materialization commit=%+v calls=%d", result.Commit, applier.calls)
	}
	if consumer.failed == nil {
		t.Fatal("committed materialization failure did not fail closed")
	}
	if state := machine.Snapshot(); !state.WriteFrozen {
		t.Fatalf("committed materialization failure left writes enabled: %+v", state)
	}
}

func TestProtectionPolicyConsumerFinishesCommittedMaterializationWithBoundedContext(t *testing.T) {
	consumer, _, applier, durable := newPolicyConsumerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	durable.onAppend = cancel
	strict := config.ProtectionLevelStrict
	result, err := consumer.ProposeAndApply(ctx, "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("materialization after request cancellation: %v", err)
	}
	if result.Commit.State.Revision != 1 || applier.calls != 1 {
		t.Fatalf("commit=%+v materializer calls=%d", result.Commit, applier.calls)
	}
	if applier.contextErr != nil {
		t.Fatalf("committed materialization inherited request cancellation: %v", applier.contextErr)
	}
	if !applier.hasDeadline {
		t.Fatal("committed materialization context has no deadline")
	}
}

func TestProtectionPolicyConsumerPreviewRejectsExternalCoordinatorRevisionAdvance(t *testing.T) {
	consumer, machine, applier, _ := newPolicyConsumerFixture(t)
	strict := config.ProtectionLevelStrict
	preview, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	current, err := consumer.handler.ConfigSnapshot(context.Background())
	if err != nil {
		t.Fatalf("external current snapshot: %v", err)
	}
	state := machine.Snapshot()
	low := config.ProtectionLevelLow
	if _, err = consumer.service.ProposeAndApply(context.Background(), current.Protection.Policy, desiredstate.ProtectionPolicyMutationRequest{
		Actor:            "external-admin",
		LeaderID:         state.LeaderID,
		ExpectedEpoch:    state.Epoch,
		ExpectedRevision: state.Revision,
		Nonce:            "external-preview-revision-advance",
		Patch:            desiredstate.ProtectionPolicyPatch{WebAttack: &low},
	}); err != nil {
		t.Fatalf("advance external state: %v", err)
	}

	result, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, preview.Binding)
	if !errors.Is(err, controlplane.ErrStaleRevision) {
		t.Fatalf("preview apply error=%v, want ErrStaleRevision", err)
	}
	if result.Commit.State.Revision != 0 {
		t.Fatalf("stale preview unexpectedly produced commit: %+v", result.Commit)
	}
	if applier.calls != 0 {
		t.Fatalf("stale preview reached materializer %d times", applier.calls)
	}
	if consumer.failed != nil || machine.Snapshot().WriteFrozen {
		t.Fatalf("stale preview froze healthy generation: failed=%v state=%+v", consumer.failed, machine.Snapshot())
	}
	if state := machine.Snapshot(); state.Revision != 1 {
		t.Fatalf("stale preview submitted a second commit: %+v", state)
	}
	if _, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, preview.Binding); !errors.Is(err, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable) {
		t.Fatalf("stale preview binding remained reusable: %v", err)
	}
}

func TestProtectionPolicyConsumerPreviewRejectsHandlerPolicyDrift(t *testing.T) {
	consumer, machine, applier, _ := newPolicyConsumerFixture(t)
	strict := config.ProtectionLevelStrict
	preview, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	live, err := consumer.handler.ConfigSnapshot(context.Background())
	if err != nil {
		t.Fatalf("handler snapshot: %v", err)
	}
	live.Protection.Policy.WebAttack = config.ProtectionLevelLow
	if err := consumer.handler.PublishMaterializedConfig(context.Background(), live); err != nil {
		t.Fatalf("publish external handler policy drift: %v", err)
	}

	result, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, preview.Binding)
	if !errors.Is(err, controlplane.ErrStaleRevision) {
		t.Fatalf("preview apply error=%v, want ErrStaleRevision", err)
	}
	if result.Commit.State.Revision != 0 || applier.calls != 0 || machine.Snapshot().Revision != 0 {
		t.Fatalf("stale handler baseline changed generation: result=%+v calls=%d state=%+v", result, applier.calls, machine.Snapshot())
	}
	if _, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, preview.Binding); !errors.Is(err, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable) {
		t.Fatalf("stale handler baseline binding remained reusable: %v", err)
	}
}

func TestProtectionPolicyConsumerPreviewStoresNormalizedBaseline(t *testing.T) {
	consumer, _, _, _ := newPolicyConsumerFixture(t)
	consumer.handler.Config.Protection.Policy = config.ProtectionPolicyConfig{WebAttack: config.ProtectionLevelLow}
	strict := config.ProtectionLevelStrict
	preview, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	stored, ok := consumer.previews[preview.Binding]
	if !ok {
		t.Fatal("preview baseline was not stored")
	}
	want := config.DefaultProtectionPolicy()
	want.WebAttack = config.ProtectionLevelLow
	if stored.before != want {
		t.Fatalf("stored baseline=%+v, want normalized %+v", stored.before, want)
	}
	if stored.after != preview.Mutation.After {
		t.Fatalf("stored approved target=%+v, want %+v", stored.after, preview.Mutation.After)
	}
}

func TestProtectionPolicyConsumerPreviewAppliesStoredApprovedTargetAfterCallerPatchMutation(t *testing.T) {
	consumer, machine, applier, _ := newPolicyConsumerFixture(t)
	requested := config.ProtectionLevelStrict
	patch := desiredstate.ProtectionPolicyPatch{WebAttack: &requested}
	preview, err := consumer.Preview(context.Background(), "admin", patch)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	// The caller still owns this pointer after Preview. Changing it must not
	// change the target authorized by the server-created binding.
	requested = config.ProtectionLevelLow
	result, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", patch, preview.Binding)
	if err != nil {
		t.Fatalf("apply approved preview: %v", err)
	}
	if result.Mutation.Before != preview.Mutation.Before || result.Mutation.After != preview.Mutation.After {
		t.Fatalf("applied mutation=%+v, want preview mutation before=%+v after=%+v", result.Mutation, preview.Mutation.Before, preview.Mutation.After)
	}
	if result.Mutation.After.WebAttack != config.ProtectionLevelStrict {
		t.Fatalf("applied target used mutated caller patch: %+v", result.Mutation.After)
	}
	committed, err := desiredstate.DecodeProtectionPolicyConfig(result.Commit.State.Desired.Payload)
	if err != nil {
		t.Fatalf("decode committed approved target: %v", err)
	}
	if committed != preview.Mutation.After {
		t.Fatalf("committed policy=%+v, want approved target %+v", committed, preview.Mutation.After)
	}
	live, err := consumer.handler.ConfigSnapshot(context.Background())
	if err != nil {
		t.Fatalf("read materialized policy: %v", err)
	}
	if live.Protection.Policy != preview.Mutation.After {
		t.Fatalf("materialized policy=%+v, want approved target %+v", live.Protection.Policy, preview.Mutation.After)
	}
	if applier.calls != 1 || machine.Snapshot().Revision != 1 {
		t.Fatalf("approved target was not committed exactly once: calls=%d state=%+v", applier.calls, machine.Snapshot())
	}
	if _, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", patch, preview.Binding); !errors.Is(err, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable) {
		t.Fatalf("successful preview binding remained reusable: %v", err)
	}
}

func TestProtectionPolicyConsumerPreviewBindingRejectsUnavailableCases(t *testing.T) {
	strict := config.ProtectionLevelStrict
	for _, tc := range []struct {
		name    string
		binding string
		expires bool
	}{
		{
			name:    "unknown binding",
			binding: "unknown-preview-binding",
		},
		{
			name:    "expired at exact expiry",
			expires: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consumer, machine, applier, _ := newPolicyConsumerFixture(t)
			preview, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
			if err != nil {
				t.Fatalf("preview: %v", err)
			}
			if tc.expires {
				stored := consumer.previews[preview.Binding]
				if stored.availableAt(stored.expires) {
					t.Fatal("preview remained available at its exact expiry")
				}
				stored.expires = time.Now()
				consumer.previews[preview.Binding] = stored
			}
			binding := preview.Binding
			if tc.binding != "" {
				binding = tc.binding
			}
			if _, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, binding); !errors.Is(err, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable) {
				t.Fatalf("preview apply error=%v, want ErrProtectionPolicyCoordinatorPreviewUnavailable", err)
			}
			if applier.calls != 0 || machine.Snapshot().Revision != 0 || machine.Snapshot().WriteFrozen {
				t.Fatalf("unavailable preview changed generation: calls=%d state=%+v", applier.calls, machine.Snapshot())
			}
		})
	}
}

func TestProtectionPolicyConsumerPreviewBindingIsConsumedAfterMismatch(t *testing.T) {
	strict := config.ProtectionLevelStrict
	for _, tc := range []struct {
		name  string
		actor string
	}{
		{name: "actor mismatch", actor: "other-admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consumer, machine, applier, _ := newPolicyConsumerFixture(t)
			preview, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
			if err != nil {
				t.Fatalf("preview: %v", err)
			}
			if _, err := consumer.ProposeAndApplyWithPreview(context.Background(), tc.actor, desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, preview.Binding); !errors.Is(err, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable) {
				t.Fatalf("mismatched preview apply error=%v, want ErrProtectionPolicyCoordinatorPreviewUnavailable", err)
			}
			if _, err := consumer.ProposeAndApplyWithPreview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict}, preview.Binding); !errors.Is(err, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable) {
				t.Fatalf("mismatched preview binding remained reusable: %v", err)
			}
			if applier.calls != 0 || machine.Snapshot().Revision != 0 || machine.Snapshot().WriteFrozen {
				t.Fatalf("mismatched preview changed generation: calls=%d state=%+v", applier.calls, machine.Snapshot())
			}
		})
	}
}

func TestProtectionPolicyConsumerPreviewPrunesAtExactExpiry(t *testing.T) {
	consumer, _, _, _ := newPolicyConsumerFixture(t)
	strict := config.ProtectionLevelStrict
	first, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("first preview: %v", err)
	}
	firstStored := consumer.previews[first.Binding]
	consumer.prunePreviewsAtLocked(firstStored.expires)
	second, err := consumer.Preview(context.Background(), "admin", desiredstate.ProtectionPolicyPatch{WebAttack: &strict})
	if err != nil {
		t.Fatalf("second preview: %v", err)
	}
	if _, ok := consumer.previews[first.Binding]; ok {
		t.Fatal("preview at exact expiry was not pruned")
	}
	if _, ok := consumer.previews[second.Binding]; !ok {
		t.Fatal("new preview missing after prune")
	}
}
