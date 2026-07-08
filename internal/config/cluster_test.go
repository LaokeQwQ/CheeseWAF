package config

import (
	"strings"
	"testing"
)

func TestClusterDefaultIsStandalone(t *testing.T) {
	cfg := Default()
	if cfg.Deployment.Mode != "standalone" {
		t.Fatalf("default deployment mode = %q, want standalone", cfg.Deployment.Mode)
	}
	if cfg.Cluster.Enabled {
		t.Fatal("cluster must be disabled by default")
	}
	if cfg.Cluster.Consensus.Provider != "builtin" {
		t.Fatalf("default cluster consensus provider = %q, want builtin", cfg.Cluster.Consensus.Provider)
	}
}

func TestClusterRejectsEnabledClusterInStandaloneMode(t *testing.T) {
	cfg := Default()
	cfg.Cluster.Enabled = true
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "deployment.mode=cluster") {
		t.Fatalf("expected standalone cluster mismatch error, got %v", err)
	}
}

func TestClusterRejectsUnsafeTwoNodeHAClaim(t *testing.T) {
	cfg := Default()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.HAMode = "multi-node-ha"
	cfg.Cluster.Nodes = []ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
	}
	if err := Validate(&cfg); err == nil {
		t.Fatal("two WAF nodes must not validate as multi-node HA")
	}
}

func TestClusterAcceptsTwoWAFNodesWithMonitorNode(t *testing.T) {
	cfg := Default()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.HAMode = "minimum-ha"
	cfg.Cluster.Nodes = []ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
		{ID: "monitor-a", Role: "monitor", AdvertiseAddr: "10.0.0.3:9444"},
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid minimum HA cluster rejected: %v", err)
	}
}

func TestClusterAcceptsDualNodeLoadBalancingWithoutHAClaim(t *testing.T) {
	cfg := Default()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.HAMode = "dual-node-load-balancing"
	cfg.Cluster.Nodes = []ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("dual-node load balancing should validate without HA claim: %v", err)
	}
}
