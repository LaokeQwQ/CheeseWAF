package traffic

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCircuitOpensAfterFailures(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := NewScheduler()
	s.ConfigureAdvanced(AdvancedOptions{
		CircuitFailures: 2,
		CircuitOpenFor:  30 * time.Second,
		Now:             func() time.Time { return now },
	})
	peers := []Peer{
		{NodeID: "a", AdvertiseAddr: "a", Weight: 1},
		{NodeID: "b", AdvertiseAddr: "b", Weight: 1},
	}
	s.ReportFailure("a")
	s.ReportFailure("a")
	got, ok := s.PickAdvanced(ModeRoundRobin, peers, "", "", "")
	if !ok || got.NodeID != "b" {
		t.Fatalf("expected only b after circuit open, got %+v ok=%v", got, ok)
	}
	// After open window, half-open allows a again.
	now = now.Add(31 * time.Second)
	healthy := s.FilterHealthy(peers)
	if len(healthy) != 2 {
		t.Fatalf("expected half-open to restore a, healthy=%+v", healthy)
	}
}

func TestStickyPickStable(t *testing.T) {
	s := NewScheduler()
	peers := []Peer{
		{NodeID: "a", AdvertiseAddr: "a"},
		{NodeID: "b", AdvertiseAddr: "b"},
		{NodeID: "c", AdvertiseAddr: "c"},
	}
	first, ok := s.PickAdvanced(ModeSticky, peers, "203.0.113.50", "", "sess-1")
	if !ok {
		t.Fatal("expected sticky pick")
	}
	second, _ := s.PickAdvanced(ModeSticky, peers, "203.0.113.99", "", "sess-1")
	if first.NodeID != second.NodeID {
		t.Fatalf("sticky key should pin peer: %s vs %s", first.NodeID, second.NodeID)
	}
}

func TestReportSuccessClearsCircuit(t *testing.T) {
	s := NewScheduler()
	s.ConfigureAdvanced(AdvancedOptions{CircuitFailures: 1, CircuitOpenFor: time.Minute})
	peers := []Peer{{NodeID: "a", AdvertiseAddr: "a"}, {NodeID: "b", AdvertiseAddr: "b"}}
	s.ReportFailure("a")
	if healthy := s.FilterHealthy(peers); len(healthy) != 1 || healthy[0].NodeID != "b" {
		t.Fatalf("expected a open, healthy=%+v", healthy)
	}
	s.ReportSuccess("a")
	if healthy := s.FilterHealthy(peers); len(healthy) != 2 {
		t.Fatalf("expected circuit clear, healthy=%+v", healthy)
	}
}

func TestPeerJSONSnakeCase(t *testing.T) {
	raw, err := json.Marshal(Peer{
		NodeID: "waf-a", AdvertiseAddr: "10.0.0.1:1", Region: "cn", Weight: 4, Online: true, CanReceive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, key := range []string{`"node_id"`, `"advertise_addr"`, `"can_receive"`} {
		if !strings.Contains(s, key) {
			t.Fatalf("missing %s in %s", key, s)
		}
	}
	if strings.Contains(s, `"NodeID"`) {
		t.Fatalf("PascalCase leaked: %s", s)
	}
}

func TestPressureDemotesWeight(t *testing.T) {
	s := NewScheduler()
	s.ConfigureAdvanced(AdvancedOptions{PressureLimit: 4})
	peers := []Peer{{NodeID: "a", AdvertiseAddr: "a", Weight: 4}, {NodeID: "b", AdvertiseAddr: "b", Weight: 4}}
	for i := 0; i < 4; i++ {
		s.Acquire("a")
	}
	healthy := s.FilterHealthy(peers)
	var a Peer
	for _, p := range healthy {
		if p.NodeID == "a" {
			a = p
		}
	}
	if a.Weight != 1 {
		t.Fatalf("pressure should demote weight to 1, got %d", a.Weight)
	}
}
