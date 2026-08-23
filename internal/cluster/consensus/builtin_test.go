package consensus

import (
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
)

func TestEvaluateElectsOnlyLocalBuiltinNode(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "waf-a", Provider: ProviderBuiltin})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{Mode: "single-node", MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 1, VotingNodeCount: 1}
	snap := c.Evaluate(status, nodes)
	if snap.LeaderID != "waf-a" {
		t.Fatalf("leader=%q want waf-a", snap.LeaderID)
	}
	if snap.LocalRole != RoleLeader {
		t.Fatalf("local role=%q want leader", snap.LocalRole)
	}
}

func TestProposeConfigVersionRequiresWritableLeader(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "waf-a", Provider: ProviderBuiltin, Now: func() time.Time {
		return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	}})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{Mode: "single-node", MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 1, VotingNodeCount: 1}
	rec, err := c.ProposeConfigVersion("v2", "sites updated", status, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "v2" || rec.LeaderID != "waf-a" {
		t.Fatalf("record=%+v", rec)
	}
	status.CanWriteConfig = false
	status.ProtectionModeReason = "no majority"
	if _, err := c.ProposeConfigVersion("v3", "blocked", status, nodes); err == nil {
		t.Fatal("expected freeze to reject proposal")
	}
}

func TestBuiltinCoordinatorRejectsSharedCluster(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "waf-a", Provider: ProviderBuiltin})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
		{NodeID: "waf-b", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{Mode: "single-node", MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 2, VotingNodeCount: 2}
	snap := c.Evaluate(status, nodes)
	if snap.CanWriteConfig || snap.MajorityConfirmed || snap.LeaderID != "" {
		t.Fatalf("builtin coordinator did not fail closed for shared cluster: %+v", snap)
	}
	if !strings.Contains(snap.Reason, "requires etcd") {
		t.Fatalf("reason=%q, want clear etcd requirement", snap.Reason)
	}
	if _, err := c.ProposeConfigVersion("v2", "unsafe", status, nodes); err == nil || !strings.Contains(err.Error(), "requires etcd") {
		t.Fatalf("expected shared-cluster proposal rejection, got %v", err)
	}
}

func TestEtcdSelectionNeverUsesBuiltinHeartbeatElection(t *testing.T) {
	c := NewCoordinator(Options{
		LocalNodeID:   "waf-a",
		Provider:      ProviderEtcd,
		EtcdEndpoints: []string{"https://etcd-a.internal:2379"},
	})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
		{NodeID: "waf-b", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{Mode: "minimum-ha", MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 2, VotingNodeCount: 2}
	snap := c.Evaluate(status, nodes)
	if snap.Provider != ProviderEtcd || !snap.EtcdConfigured {
		t.Fatalf("unexpected etcd snapshot metadata: %+v", snap)
	}
	if snap.CanWriteConfig || snap.MajorityConfirmed || snap.LeaderID != "" || snap.LocalRole != RoleObserver {
		t.Fatalf("etcd selection fell back to builtin election: %+v", snap)
	}
	if !strings.Contains(snap.Reason, "etcd-backed coordinator") {
		t.Fatalf("reason=%q, want unavailable etcd coordinator explanation", snap.Reason)
	}
	if _, err := c.ProposeConfigVersion("v2", "unsafe", status, nodes); err == nil || !strings.Contains(err.Error(), "etcd-backed coordinator") {
		t.Fatalf("expected etcd proposal rejection, got %v", err)
	}
}
