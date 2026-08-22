package traffic

import (
	"strings"
	"time"
)

const (
	ModeSticky = "sticky"

	// Default circuit thresholds.
	defaultCircuitFailures = 3
	defaultCircuitOpenFor  = 30 * time.Second
	defaultPressureLimit   = 32
	maxCircuitMapSize      = 1000
)

type circuitState struct {
	failures int
	openedAt time.Time
	probeAt  time.Time
}

// AdvancedOptions tunes stickiness, circuit breaking, and pressure demotion.
type AdvancedOptions struct {
	CircuitFailures int
	CircuitOpenFor  time.Duration
	PressureLimit   int
	Now             func() time.Time
}

// Ensure advanced fields on Scheduler.
func (s *Scheduler) ensureAdvanced() {
	if s == nil {
		return
	}
	if s.circuits == nil {
		s.circuits = map[string]circuitState{}
	}
	if s.pressureLimit <= 0 {
		s.pressureLimit = defaultPressureLimit
	}
	if s.circuitFailures <= 0 {
		s.circuitFailures = defaultCircuitFailures
	}
	if s.circuitOpenFor <= 0 {
		s.circuitOpenFor = defaultCircuitOpenFor
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
}

// ConfigureAdvanced applies optional tuning.
func (s *Scheduler) ConfigureAdvanced(opts AdvancedOptions) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if opts.CircuitFailures > 0 {
		s.circuitFailures = opts.CircuitFailures
	}
	if opts.CircuitOpenFor > 0 {
		s.circuitOpenFor = opts.CircuitOpenFor
	}
	if opts.PressureLimit > 0 {
		s.pressureLimit = opts.PressureLimit
	}
	if opts.Now != nil {
		s.now = opts.Now
	}
	s.ensureAdvanced()
}

// ReportFailure opens a circuit after repeated failures.
func (s *Scheduler) ReportFailure(nodeID string) {
	if s == nil || strings.TrimSpace(nodeID) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureAdvanced()
	if len(s.circuits) >= maxCircuitMapSize {
		s.pruneOldCircuits()
	}
	state := s.circuits[nodeID]
	state.failures++
	if state.failures >= s.circuitFailures {
		state.openedAt = s.now()
		state.probeAt = time.Time{}
	}
	s.circuits[nodeID] = state
}

// ReportSuccess clears circuit state for a peer.
func (s *Scheduler) ReportSuccess(nodeID string) {
	if s == nil || strings.TrimSpace(nodeID) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.circuits != nil {
		delete(s.circuits, nodeID)
	}
}

// FilterHealthy drops peers with open circuits and applies pressure demotion weights.
func (s *Scheduler) FilterHealthy(peers []Peer) []Peer {
	if s == nil || len(peers) == 0 {
		return peers
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureAdvanced()
	now := s.now()
	out := make([]Peer, 0, len(peers))
	for _, peer := range peers {
		state, open := s.circuits[peer.NodeID]
		if open && !state.openedAt.IsZero() && now.Sub(state.openedAt) < s.circuitOpenFor {
			continue
		}
		if open && !state.openedAt.IsZero() && now.Sub(state.openedAt) >= s.circuitOpenFor {
			if !state.probeAt.IsZero() && now.Sub(state.probeAt) < s.circuitOpenFor {
				continue
			}
			// Reserve one half-open probe. A missing report expires after one open interval.
			state.probeAt = now
			s.circuits[peer.NodeID] = state
		}
		w := peer.Weight
		if w <= 0 {
			w = 1
		}
		load := s.inflight[peer.NodeID]
		if s.pressureLimit > 0 && load >= s.pressureLimit {
			// Demote under pressure: keep eligible but with minimal weight.
			w = 1
		} else if s.pressureLimit > 0 && load > s.pressureLimit/2 {
			if w > 1 {
				w = w / 2
			}
		}
		peer.Weight = w
		out = append(out, peer)
	}
	return out
}

func (s *Scheduler) pruneOldCircuits() {
	if len(s.circuits) < maxCircuitMapSize {
		return
	}
	now := s.now()
	for nodeID, state := range s.circuits {
		if !state.openedAt.IsZero() && now.Sub(state.openedAt) >= s.circuitOpenFor*2 {
			delete(s.circuits, nodeID)
		}
	}
	if len(s.circuits) >= maxCircuitMapSize {
		for nodeID := range s.circuits {
			delete(s.circuits, nodeID)
			if len(s.circuits) < maxCircuitMapSize/2 {
				break
			}
		}
	}
}

// PickAdvanced applies circuit/pressure filters then standard pick modes including sticky.
func (s *Scheduler) PickAdvanced(mode string, peers []Peer, clientIP, preferRegion, stickyKey string) (Peer, bool) {
	filtered := s.FilterHealthy(peers)
	if len(filtered) == 0 {
		return Peer{}, false
	}
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == ModeSticky || mode == "session" {
		key := strings.TrimSpace(stickyKey)
		if key == "" {
			key = clientIP
		}
		return pickIPHash(filtered, key), true
	}
	return s.Pick(mode, filtered, clientIP, preferRegion)
}
