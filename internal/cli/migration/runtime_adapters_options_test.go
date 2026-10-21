package migration

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
)

func TestNativeRaftOptionsFromConfigCarriesInitialVoters(t *testing.T) {
	cfg := config.Default()
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Cluster.NodeID = "node-b"
	cfg.Cluster.Consensus.NativeRaft.Mode = "join"
	cfg.Cluster.Consensus.NativeRaft.DataDir = "./data/cluster/native-raft"
	cfg.Cluster.Consensus.NativeRaft.InitialVoters = []config.NativeRaftVoter{{ID: "seed-a", Address: "raft-a.example:9451"}}
	cfg.Cluster.Interconnect.CAFile = "/run/cheesewaf/cluster/ca.pem"
	cfg.Cluster.Interconnect.CertFile = "/run/cheesewaf/cluster/node.crt"
	cfg.Cluster.Interconnect.KeyFile = "/run/cheesewaf/cluster/node.key"
	cfg.Setup.DataDir = t.TempDir()

	options, err := nativeRaftOptionsFromConfig(&cfg)
	if err != nil {
		t.Fatalf("nativeRaftOptionsFromConfig error=%v", err)
	}
	want := []nativeraft.Member{{ID: "seed-a", Address: "raft-a.example:9451"}}
	if !reflect.DeepEqual(options.InitialVoters, want) {
		t.Fatalf("InitialVoters=%+v, want %+v", options.InitialVoters, want)
	}
	if options.DataDir != filepath.Join(cfg.Setup.DataDir, "./data/cluster/native-raft") {
		t.Fatalf("DataDir=%q", options.DataDir)
	}
}

func TestNativeRaftOptionsFromConfigRejectsInvalidInitialVoter(t *testing.T) {
	cfg := config.Default()
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Cluster.Consensus.NativeRaft.Mode = "join"
	cfg.Cluster.Interconnect.CAFile = "/run/ca.pem"
	cfg.Cluster.Interconnect.CertFile = "/run/node.crt"
	cfg.Cluster.Interconnect.KeyFile = "/run/node.key"
	cfg.Cluster.Consensus.NativeRaft.InitialVoters = []config.NativeRaftVoter{{ID: "seed-a", Address: "raft-a.example:0"}}
	if _, err := nativeRaftOptionsFromConfig(&cfg); !errors.Is(err, setupmigration.ErrPrerequisiteUnavailable) {
		t.Fatalf("error=%v, want prerequisite-unavailable rejection", err)
	}
}
