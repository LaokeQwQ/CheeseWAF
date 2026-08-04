// Package traffic implements M4-style peer selection among cluster WAF nodes.
package traffic

import (
	"hash/fnv"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
)

const (
	ModeRoundRobin = "round_robin"
	ModeWeighted   = "weighted"
	ModeIPHash     = "ip_hash"
	ModeLeastConn  = "least_conn"
	ModeRegionPref = "region_prefer"
)

// Peer is a traffic-eligible WAF node.
type Peer struct {
	NodeID        string `json:"node_id"`
	AdvertiseAddr string `json:"advertise_addr"`
	Region        string `json:"region,omitempty"`
	Weight        int    `json:"weight"`
	Online        bool   `json:"online"`
	CanReceive    bool   `json:"can_receive"`
}

// Scheduler picks among eligible peers.
type Scheduler struct {
	mu              sync.Mutex
	rr              int
	inflight        map[string]int
	circuits        map[string]circuitState
	circuitFailures int
	circuitOpenFor  time.Duration
	pressureLimit   int
	now             func() time.Time
}

func NewScheduler() *Scheduler {
	s := &Scheduler{inflight: map[string]int{}}
	s.ensureAdvanced()
	return s
}

// EligiblePeers filters runtime nodes to online WAF nodes that accept traffic.
func EligiblePeers(nodes []cluster.RuntimeNodeStatus) []Peer {
	out := make([]Peer, 0, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.Role) != "" && node.Role != "waf" {
			continue
		}
		if node.State != cluster.NodeStateOnline || !node.CanReceiveTraffic {
			continue
		}
		addr := strings.TrimSpace(node.AdvertiseAddr)
		if addr == "" {
			continue
		}
		// Default weight leaves headroom so pressure demotion can reduce it.
		weight := 4
		out = append(out, Peer{
			NodeID:        node.NodeID,
			AdvertiseAddr: addr,
			Region:        node.Region,
			Weight:        weight,
			Online:        true,
			CanReceive:    true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Pick selects a peer. preferRegion is used for region_prefer mode.
func (s *Scheduler) Pick(mode string, peers []Peer, clientIP, preferRegion string) (Peer, bool) {
	if len(peers) == 0 {
		return Peer{}, false
	}
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		mode = ModeRoundRobin
	}
	switch mode {
	case ModeIPHash:
		return pickIPHash(peers, clientIP), true
	case ModeLeastConn:
		return s.pickLeastConn(peers), true
	case ModeRegionPref:
		return pickRegionPrefer(peers, preferRegion, clientIP), true
	case ModeWeighted:
		return pickWeightedRoundRobin(s, peers), true
	default:
		return pickRoundRobin(s, peers), true
	}
}

func (s *Scheduler) Acquire(nodeID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.inflight[nodeID]++
	s.mu.Unlock()
}

func (s *Scheduler) Release(nodeID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.inflight[nodeID] > 0 {
		s.inflight[nodeID]--
	}
	s.mu.Unlock()
}

func pickRoundRobin(s *Scheduler, peers []Peer) Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rr < 0 {
		s.rr = 0
	}
	peer := peers[s.rr%len(peers)]
	s.rr++
	return peer
}

func pickWeightedRoundRobin(s *Scheduler, peers []Peer) Peer {
	expanded := make([]Peer, 0, len(peers)*2)
	for _, peer := range peers {
		w := peer.Weight
		if w <= 0 {
			w = 1
		}
		for i := 0; i < w; i++ {
			expanded = append(expanded, peer)
		}
	}
	return pickRoundRobin(s, expanded)
}

func pickIPHash(peers []Peer, clientIP string) Peer {
	if clientIP == "" {
		return peers[0]
	}
	host := clientIP
	if h, _, err := net.SplitHostPort(clientIP); err == nil {
		host = h
	}
	sum := fnv.New32a()
	_, _ = sum.Write([]byte(host))
	return peers[int(sum.Sum32())%len(peers)]
}

func (s *Scheduler) pickLeastConn(peers []Peer) Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	best := peers[0]
	bestLoad := s.inflight[best.NodeID]
	for _, peer := range peers[1:] {
		load := s.inflight[peer.NodeID]
		if load < bestLoad || (load == bestLoad && peer.NodeID < best.NodeID) {
			best = peer
			bestLoad = load
		}
	}
	return best
}

func pickRegionPrefer(peers []Peer, preferRegion, clientIP string) Peer {
	preferRegion = strings.TrimSpace(preferRegion)
	if preferRegion != "" {
		local := make([]Peer, 0, len(peers))
		for _, peer := range peers {
			if strings.EqualFold(peer.Region, preferRegion) {
				local = append(local, peer)
			}
		}
		if len(local) > 0 {
			return pickIPHash(local, clientIP)
		}
	}
	return pickIPHash(peers, clientIP)
}
