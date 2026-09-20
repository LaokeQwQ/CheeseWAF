package materializer

import (
	"context"
	"errors"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

type coordinatorMaterializerConsensus struct {
	state controlplane.State
}

func (s *coordinatorMaterializerConsensus) Current(context.Context, string) (controlplane.State, error) {
	return s.state, nil
}

func (s *coordinatorMaterializerConsensus) Propose(_ context.Context, commit controlplane.Commit) error {
	s.state = commit.State
	return nil
}

type coordinatorMaterializerDurable struct {
	state controlplane.State
}

func materializerStringPtr(value string) *string { return &value }

func (s *coordinatorMaterializerDurable) LoadState(context.Context, string) (controlplane.State, error) {
	return s.state, nil
}

func (s *coordinatorMaterializerDurable) AppendCommit(_ context.Context, commit controlplane.Commit) error {
	s.state = commit.State
	return nil
}

func TestCoordinatorCommitFlowsIntoProtectionMaterializer(t *testing.T) {
	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	initialState := machine.Snapshot()
	consensus := &coordinatorMaterializerConsensus{state: initialState}
	durable := &coordinatorMaterializerDurable{state: initialState}
	coordinator, err := controlplane.NewCoordinator(machine, consensus, durable)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorService, err := desiredstate.NewProtectionPolicyCoordinatorService(
		desiredstate.NewProtectionPolicyMutationService(), coordinator,
	)
	if err != nil {
		t.Fatal(err)
	}

	local := config.Default()
	local.Setup.DataDir = "/var/lib/cheesewaf"
	local.Storage.ManagementPostgreSQL.DSN = "postgres://user:password@example.invalid/management"
	local.Protection.Bot.Secret = "node-local-secret"
	previous, err := config.Clone(&local)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinatorService.ProposeAndApply(context.Background(), local.Protection.Policy, desiredstate.ProtectionPolicyMutationRequest{
		Actor:            "operator-a",
		LeaderID:         "node-a",
		ExpectedEpoch:    1,
		ExpectedRevision: 0,
		Nonce:            "policy-change-1",
		Patch: desiredstate.ProtectionPolicyPatch{
			WebAttack: materializerStringPtr(config.ProtectionLevelHigh),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Commit.State.Revision != 1 || machine.Snapshot().Revision != 1 {
		t.Fatalf("coordinator result=%+v machine=%+v, want revision 1", result.Commit, machine.Snapshot())
	}

	journal, err := NewJournalStore(t.TempDir(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	persistN, runtimeN, rollbackN := 0, 0, 0
	applier, err := NewProtectionPolicyApplier(ProtectionPolicyApplierOptions{
		Validator: machine,
		Snapshot: func(context.Context) (*config.Config, error) {
			return config.Clone(&local)
		},
		PreviousSnapshot: func(context.Context) (*config.Config, error) {
			return config.Clone(previous)
		},
		PersistConfig: func(_ context.Context, candidate *config.Config) error {
			persistN++
			cloned, cloneErr := config.Clone(candidate)
			if cloneErr != nil {
				return cloneErr
			}
			local = *cloned
			return nil
		},
		ApplyRuntime: func(_ context.Context, candidate *config.Config) error {
			runtimeN++
			if candidate.Protection.Policy != result.Mutation.After {
				return errors.New("runtime received a policy different from the committed mutation")
			}
			return nil
		},
		RollbackRuntime: func(_ context.Context, candidate *config.Config) error {
			rollbackN++
			if candidate == nil {
				return errors.New("rollback received nil config")
			}
			return nil
		},
		Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.ApplyCommitted(context.Background(), result.Commit); err != nil {
		t.Fatal(err)
	}
	if err := applier.ApplyCommitted(context.Background(), result.Commit); err != nil {
		t.Fatal(err)
	}
	if persistN != 1 || runtimeN != 1 || rollbackN != 0 {
		t.Fatalf("materializer callbacks persist=%d runtime=%d rollback=%d, want 1/1/0", persistN, runtimeN, rollbackN)
	}
	if local.Protection.Policy != result.Mutation.After {
		t.Fatalf("local policy=%+v, want committed policy %+v", local.Protection.Policy, result.Mutation.After)
	}
	if local.Setup.DataDir != "/var/lib/cheesewaf" || local.Storage.ManagementPostgreSQL.DSN == "" || local.Protection.Bot.Secret != "node-local-secret" {
		t.Fatal("materializer did not preserve node-local fields")
	}
	receipt, err := journal.LoadJournal()
	if err != nil || receipt.Phase != PhaseApplied {
		t.Fatalf("receipt=%+v err=%v, want applied", receipt, err)
	}
}
