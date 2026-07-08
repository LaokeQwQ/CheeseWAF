package cluster

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRuntimeHeartbeatUnlocksMinimumHAWhenMajorityIsOnline(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	registry := NewHeartbeatRegistry(HeartbeatRegistryOptions{
		TTL: 30 * time.Second,
		Now: func() time.Time {
			return now
		},
	})
	cfg := minimumHATestConfig()

	status := FromConfigWithRuntime(&cfg, registry, "zh-CN")
	if status.MajorityConfirmed {
		t.Fatalf("majority should not be confirmed with only local node online: %+v", status)
	}
	if status.CanWriteConfig {
		t.Fatalf("config writes must freeze without majority: %+v", status)
	}
	if status.OnlineVotingCount != 1 || status.VotingNodeCount != 3 {
		t.Fatalf("unexpected voting counts: %+v", status)
	}

	if _, err := registry.Record(Heartbeat{NodeID: "monitor-a", Role: "monitor"}); err != nil {
		t.Fatal(err)
	}
	status = FromConfigWithRuntime(&cfg, registry, "zh-CN")
	if !status.MajorityConfirmed || !status.CanWriteConfig {
		t.Fatalf("monitor heartbeat should confirm 2/3 majority and allow writes: %+v", status)
	}
	if status.OnlineVotingCount != 2 {
		t.Fatalf("online voters=%d, want 2", status.OnlineVotingCount)
	}
}

func TestRuntimeHeartbeatTimeoutReturnsProtectionMode(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	registry := NewHeartbeatRegistry(HeartbeatRegistryOptions{
		TTL: 30 * time.Second,
		Now: func() time.Time {
			return now
		},
	})
	cfg := minimumHATestConfig()
	if _, err := registry.Record(Heartbeat{NodeID: "monitor-a", Role: "monitor"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)

	status := FromConfigWithRuntime(&cfg, registry, "en-US")
	if status.MajorityConfirmed || status.CanWriteConfig {
		t.Fatalf("expired heartbeat must not confirm majority: %+v", status)
	}
	nodes := RuntimeNodes(&cfg, registry, "en-US")
	var monitor RuntimeNodeStatus
	for _, node := range nodes {
		if node.NodeID == "monitor-a" {
			monitor = node
			break
		}
	}
	if monitor.State != NodeStateStale || monitor.LastSeenAgoSeconds < 31 {
		t.Fatalf("monitor runtime state was not stale: %+v", monitor)
	}
}

func TestRuntimeHeartbeatCannotConfirmMajorityWhenNodeCannotWriteConfig(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	registry := NewHeartbeatRegistry(HeartbeatRegistryOptions{
		TTL: 30 * time.Second,
		Now: func() time.Time {
			return now
		},
	})
	cfg := minimumHATestConfig()
	if _, err := registry.Record(Heartbeat{
		NodeID:            "monitor-a",
		Role:              "monitor",
		CanWriteConfig:    false,
		CanWriteConfigSet: true,
	}); err != nil {
		t.Fatal(err)
	}

	status := FromConfigWithRuntime(&cfg, registry, "zh-CN")
	if status.MajorityConfirmed || status.CanWriteConfig {
		t.Fatalf("node that cannot write config must not confirm write majority: %+v", status)
	}
	if status.OnlineVotingCount != 1 {
		t.Fatalf("online write-capable voters=%d, want 1", status.OnlineVotingCount)
	}
}

func TestRuntimeDualNodeLoadBalancingDoesNotRequireMajority(t *testing.T) {
	cfg := config.Default()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Cluster.NodeID = "waf-a"
	cfg.Cluster.HAMode = "dual-node-load-balancing"
	cfg.Cluster.Nodes = []config.ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
	}

	status := FromConfigWithRuntime(&cfg, NewHeartbeatRegistry(HeartbeatRegistryOptions{}), "zh-CN")
	if !status.MajorityConfirmed || !status.CanWriteConfig || !status.CanReceiveTraffic {
		t.Fatalf("dual-node load balancing should stay operable without HA majority: %+v", status)
	}
	if status.OnlineVotingCount != 1 || status.VotingNodeCount != 2 {
		t.Fatalf("unexpected voting counts: %+v", status)
	}
}

func minimumHATestConfig() config.Config {
	cfg := config.Default()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Cluster.NodeID = "waf-a"
	cfg.Cluster.HAMode = "minimum-ha"
	cfg.Cluster.Protection.FreezeWritesWithoutMajority = true
	cfg.Cluster.Protection.AllowTrafficInProtectionMode = true
	cfg.Cluster.Nodes = []config.ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
		{ID: "monitor-a", Role: "monitor", AdvertiseAddr: "10.0.0.3:9444"},
	}
	return cfg
}
