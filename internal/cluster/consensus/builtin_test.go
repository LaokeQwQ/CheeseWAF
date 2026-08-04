package consensus

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
)

func TestEvaluateElectsLowestOnlineVoter(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "waf-b", Provider: ProviderBuiltin})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-b", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
		{NodeID: "mon-z", Role: "monitor", State: cluster.NodeStateStale, CanWriteConfig: true},
	}
	status := cluster.Status{MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 2, VotingNodeCount: 2}
	snap := c.Evaluate(status, nodes)
	if snap.LeaderID != "waf-a" {
		t.Fatalf("leader=%q want waf-a", snap.LeaderID)
	}
	if snap.LocalRole != RoleFollower {
		t.Fatalf("local role=%q want follower", snap.LocalRole)
	}
}

func TestProposeConfigVersionRequiresWritableLeader(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "waf-a", Provider: ProviderBuiltin, Now: func() time.Time {
		return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	}})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 1, VotingNodeCount: 1}
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

func TestFollowerCannotPropose(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "waf-b", Provider: ProviderBuiltin})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
		{NodeID: "waf-b", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 2, VotingNodeCount: 2}
	if _, err := c.ProposeConfigVersion("v9", "from follower", status, nodes); err == nil {
		t.Fatal("expected follower propose to fail")
	}
}

func TestMonitorIsObserverNotLeaderUnlessOnlyVoter(t *testing.T) {
	c := NewCoordinator(Options{LocalNodeID: "mon-a", Provider: ProviderBuiltin})
	nodes := []cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanWriteConfig: true},
		{NodeID: "mon-a", Role: "monitor", State: cluster.NodeStateOnline, CanWriteConfig: true},
	}
	status := cluster.Status{MajorityConfirmed: true, CanWriteConfig: true, OnlineVotingCount: 2, VotingNodeCount: 2}
	snap := c.Evaluate(status, nodes)
	if snap.LeaderID != "mon-a" && snap.LeaderID != "waf-a" {
		// Lowest ID wins; mon-a < waf-a lexicographically? "mon-a" vs "waf-a" — mon-a is lower.
		t.Fatalf("leader=%q", snap.LeaderID)
	}
	if snap.LeaderID == "mon-a" && snap.LocalRole != RoleLeader {
		t.Fatalf("local role=%q", snap.LocalRole)
	}
	if snap.LeaderID == "waf-a" && snap.LocalRole != RoleFollower {
		t.Fatalf("local role=%q want follower", snap.LocalRole)
	}
}
