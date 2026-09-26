package cli

import (
	"testing"

	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

func TestProductionStartupPolicyMaterializationBindsMigrationAndTypedPolicy(t *testing.T) {
	initial := []byte(`{"schema_version":1,"cluster_id":"cluster-a"}`)
	handoff := climigration.ProductionHandoff{ClusterID: "cluster-a", InitialStateHash: controlplane.Digest(initial)}
	state := controlplane.State{
		ClusterID: "cluster-a", Revision: 1,
		Desired: controlplane.DesiredState{
			Version: "cheesewaf-config-v1", Digest: handoff.InitialStateHash, Payload: initial,
		},
	}
	if materialize, err := productionStartupPolicyMaterialization(state, handoff); err != nil || materialize {
		t.Fatalf("exact migration anchor materialize=%t err=%v, want no policy materialization", materialize, err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*controlplane.State, *climigration.ProductionHandoff)
	}{
		{"changed payload", func(s *controlplane.State, _ *climigration.ProductionHandoff) { s.Desired.Payload = []byte(`{}`) }},
		{"changed handoff", func(_ *controlplane.State, h *climigration.ProductionHandoff) {
			h.InitialStateHash = controlplane.Digest([]byte(`{}`))
		}},
		{"noninitial revision", func(s *controlplane.State, _ *climigration.ProductionHandoff) { s.Revision = 2 }},
		{"other cluster", func(s *controlplane.State, _ *climigration.ProductionHandoff) { s.ClusterID = "cluster-b" }},
		{"unsupported version", func(s *controlplane.State, _ *climigration.ProductionHandoff) { s.Desired.Version = "management.v2" }},
		{"missing revision", func(s *controlplane.State, _ *climigration.ProductionHandoff) { s.Revision = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changedState, changedHandoff := state, handoff
			tc.mutate(&changedState, &changedHandoff)
			if _, err := productionStartupPolicyMaterialization(changedState, changedHandoff); err == nil {
				t.Fatal("invalid production startup state was accepted")
			}
		})
	}

	payload, digest, err := desiredstate.EncodeProtectionPolicy(config.DefaultProtectionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	state.Desired = controlplane.DesiredState{Version: desiredstate.Version, Digest: digest, Payload: payload}
	state.Revision = 2
	if materialize, err := productionStartupPolicyMaterialization(state, handoff); err != nil || !materialize {
		t.Fatalf("typed protection policy materialize=%t err=%v, want materialization", materialize, err)
	}
	state.Revision = 1
	if _, err := productionStartupPolicyMaterialization(state, handoff); err == nil {
		t.Fatal("typed policy without a migration anchor was accepted")
	}
	state.Revision = 2
	state.Desired.Payload = []byte(`{"version":"management.v1"}`)
	state.Desired.Digest = controlplane.Digest(state.Desired.Payload)
	if _, err := productionStartupPolicyMaterialization(state, handoff); err == nil {
		t.Fatal("noncanonical or incomplete typed policy was accepted")
	}
}
