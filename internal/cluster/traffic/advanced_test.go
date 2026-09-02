package traffic

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

func TestHalfOpenCircuitAllowsSingleConcurrentProbe(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := NewScheduler()
	s.ConfigureAdvanced(AdvancedOptions{
		CircuitFailures: 1,
		CircuitOpenFor:  time.Second,
		Now:             func() time.Time { return now },
	})
	s.ReportFailure("a")
	now = now.Add(2 * time.Second)
	peers := []Peer{{NodeID: "a", AdvertiseAddr: "a", Weight: 1}}

	const callers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if peer, ok := s.PickAdvanced(ModeRoundRobin, peers, "", "", ""); ok && peer.NodeID == "a" {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("half-open circuit admitted %d probes, want 1", got)
	}
}

func TestHalfOpenProbeReservationExpires(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := NewScheduler()
	s.ConfigureAdvanced(AdvancedOptions{CircuitFailures: 1, CircuitOpenFor: time.Second, Now: func() time.Time { return now }})
	s.ReportFailure("a")
	now = now.Add(2 * time.Second)
	peers := []Peer{{NodeID: "a", AdvertiseAddr: "a"}}
	if _, ok := s.PickAdvanced(ModeRoundRobin, peers, "", "", ""); !ok {
		t.Fatal("first half-open probe was not admitted")
	}
	if _, ok := s.PickAdvanced(ModeRoundRobin, peers, "", "", ""); ok {
		t.Fatal("probe reservation did not block a second probe")
	}
	now = now.Add(2 * time.Second)
	if _, ok := s.PickAdvanced(ModeRoundRobin, peers, "", "", ""); !ok {
		t.Fatal("stale probe reservation did not expire")
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

func TestReportFailureBoundsCircuitMap(t *testing.T) {
	s := NewScheduler()
	for i := 0; i <= maxCircuitMapSize; i++ {
		s.ReportFailure(fmt.Sprintf("node-%d", i))
	}

	s.mu.Lock()
	count := len(s.circuits)
	_, newestPresent := s.circuits[fmt.Sprintf("node-%d", maxCircuitMapSize)]
	s.mu.Unlock()
	if count >= maxCircuitMapSize {
		t.Fatalf("circuit map was not compacted at capacity: %d", count)
	}
	if !newestPresent {
		t.Fatal("new failure was dropped while compacting circuit map")
	}
}

func TestReportFailurePrunesExpiredOpenCircuits(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := NewScheduler()
	s.ConfigureAdvanced(AdvancedOptions{
		CircuitFailures: 1,
		CircuitOpenFor:  time.Second,
		Now:             func() time.Time { return now },
	})
	for i := 0; i < maxCircuitMapSize; i++ {
		s.ReportFailure(fmt.Sprintf("expired-%d", i))
	}
	now = now.Add(3 * time.Second)
	s.ReportFailure("current")

	s.mu.Lock()
	count := len(s.circuits)
	_, currentPresent := s.circuits["current"]
	s.mu.Unlock()
	if count != 1 || !currentPresent {
		t.Fatalf("expired circuits were not pruned: count=%d current=%v", count, currentPresent)
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
