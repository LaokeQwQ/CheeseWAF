package traffic

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
)

func TestEligiblePeersFiltersOfflineAndMonitor(t *testing.T) {
	peers := EligiblePeers([]cluster.RuntimeNodeStatus{
		{NodeID: "waf-a", Role: "waf", State: cluster.NodeStateOnline, CanReceiveTraffic: true, AdvertiseAddr: "10.0.0.1:1"},
		{NodeID: "waf-b", Role: "waf", State: cluster.NodeStateStale, CanReceiveTraffic: true, AdvertiseAddr: "10.0.0.2:1"},
		{NodeID: "mon-a", Role: "monitor", State: cluster.NodeStateOnline, CanReceiveTraffic: true, AdvertiseAddr: "10.0.0.3:1"},
		{NodeID: "waf-c", Role: "waf", State: cluster.NodeStateOnline, CanReceiveTraffic: false, AdvertiseAddr: "10.0.0.4:1"},
	})
	if len(peers) != 1 || peers[0].NodeID != "waf-a" {
		t.Fatalf("peers=%+v", peers)
	}
}

func TestSchedulerLeastConn(t *testing.T) {
	s := NewScheduler()
	peers := []Peer{{NodeID: "a", AdvertiseAddr: "a"}, {NodeID: "b", AdvertiseAddr: "b"}}
	s.Acquire("a")
	s.Acquire("a")
	got, ok := s.Pick(ModeLeastConn, peers, "", "")
	if !ok || got.NodeID != "b" {
		t.Fatalf("expected b under least_conn, got %+v ok=%v", got, ok)
	}
}

func TestSchedulerIPHashStable(t *testing.T) {
	s := NewScheduler()
	peers := []Peer{
		{NodeID: "a", AdvertiseAddr: "a"},
		{NodeID: "b", AdvertiseAddr: "b"},
		{NodeID: "c", AdvertiseAddr: "c"},
	}
	first, _ := s.Pick(ModeIPHash, peers, "203.0.113.10", "")
	second, _ := s.Pick(ModeIPHash, peers, "203.0.113.10", "")
	if first.NodeID != second.NodeID {
		t.Fatalf("ip hash unstable: %s vs %s", first.NodeID, second.NodeID)
	}
}
