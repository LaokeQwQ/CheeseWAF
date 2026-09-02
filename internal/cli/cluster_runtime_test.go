package cli

import (
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestInitializeClusterRuntimeRejectsBuiltinForSharedCluster(t *testing.T) {
	tests := []struct {
		name   string
		nodeID string
		nodes  []config.ClusterNodeConfig
	}{
		{
			name: "multiple configured nodes",
			nodes: []config.ClusterNodeConfig{
				{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
				{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
			},
		},
		{
			name:   "local node omitted from configured nodes",
			nodeID: "waf-local",
			nodes: []config.ClusterNodeConfig{
				{ID: "waf-remote", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Setup.DataDir = t.TempDir()
			cfg.Deployment.Mode = "cluster"
			cfg.Cluster.Enabled = true
			cfg.Cluster.HAMode = "single-node"
			cfg.Cluster.NodeID = tt.nodeID
			cfg.Cluster.Consensus.Provider = "builtin"
			cfg.Cluster.Nodes = tt.nodes

			_, _, err := initializeClusterRuntime(&cfg, nil)
			if err == nil || !strings.Contains(err.Error(), "requires cluster.consensus.provider=etcd") {
				t.Fatalf("expected startup consensus validation error, got %v", err)
			}
		})
	}
}
