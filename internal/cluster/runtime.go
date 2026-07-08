package cluster

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	DefaultHeartbeatTTL = 30 * time.Second

	NodeStateOnline  = "online"
	NodeStateStale   = "stale"
	NodeStateUnknown = "unknown"
)

type HeartbeatRegistryOptions struct {
	TTL time.Duration
	Now func() time.Time
}

type HeartbeatRegistry struct {
	mu      sync.RWMutex
	ttl     time.Duration
	now     func() time.Time
	records map[string]Heartbeat
}

type Heartbeat struct {
	NodeID               string    `json:"node_id"`
	Role                 string    `json:"role,omitempty"`
	AdvertiseAddr        string    `json:"advertise_addr,omitempty"`
	ConfigVersion        string    `json:"config_version,omitempty"`
	CanReceiveTraffic    bool      `json:"can_receive_traffic"`
	CanReceiveTrafficSet bool      `json:"-"`
	CanWriteConfig       bool      `json:"can_write_config"`
	CanWriteConfigSet    bool      `json:"-"`
	RecordedAt           time.Time `json:"recorded_at"`
}

type RuntimeNodeStatus struct {
	NodeID             string     `json:"node_id"`
	Role               string     `json:"role"`
	AdvertiseAddr      string     `json:"advertise_addr,omitempty"`
	Region             string     `json:"region,omitempty"`
	Datacenter         string     `json:"datacenter,omitempty"`
	State              string     `json:"state"`
	Local              bool       `json:"local"`
	LastHeartbeatAt    *time.Time `json:"last_heartbeat_at,omitempty"`
	LastSeenAgoSeconds int64      `json:"last_seen_ago_seconds,omitempty"`
	ConfigVersion      string     `json:"config_version,omitempty"`
	CanReceiveTraffic  bool       `json:"can_receive_traffic"`
	CanWriteConfig     bool       `json:"can_write_config"`
	Reason             string     `json:"reason,omitempty"`
}

func NewHeartbeatRegistry(opts HeartbeatRegistryOptions) *HeartbeatRegistry {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultHeartbeatTTL
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &HeartbeatRegistry{
		ttl:     ttl,
		now:     now,
		records: map[string]Heartbeat{},
	}
}

func (r *HeartbeatRegistry) Record(input Heartbeat) (Heartbeat, error) {
	if r == nil {
		return Heartbeat{}, fmt.Errorf("heartbeat registry is unavailable")
	}
	nodeID := strings.TrimSpace(input.NodeID)
	if nodeID == "" {
		return Heartbeat{}, fmt.Errorf("node id is required")
	}
	record := input
	record.NodeID = nodeID
	record.Role = strings.TrimSpace(record.Role)
	record.AdvertiseAddr = strings.TrimSpace(record.AdvertiseAddr)
	record.ConfigVersion = strings.TrimSpace(record.ConfigVersion)
	record.RecordedAt = r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[nodeID] = record
	return record, nil
}

func (r *HeartbeatRegistry) Snapshot() map[string]Heartbeat {
	if r == nil {
		return map[string]Heartbeat{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Heartbeat, len(r.records))
	for id, record := range r.records {
		out[id] = record
	}
	return out
}

func (r *HeartbeatRegistry) ttlOrDefault() time.Duration {
	if r == nil || r.ttl <= 0 {
		return DefaultHeartbeatTTL
	}
	return r.ttl
}

func (r *HeartbeatRegistry) nowOrUTC() time.Time {
	if r == nil || r.now == nil {
		return time.Now().UTC()
	}
	return r.now().UTC()
}

func RuntimeNodes(cfg *config.Config, registry *HeartbeatRegistry, lang string) []RuntimeNodeStatus {
	if cfg == nil || !cfg.Cluster.Enabled || cfg.Deployment.Mode != "cluster" {
		return nil
	}
	now := registry.nowOrUTC()
	ttl := registry.ttlOrDefault()
	records := registry.Snapshot()
	nodes := make([]RuntimeNodeStatus, 0, len(cfg.Cluster.Nodes))
	seen := map[string]struct{}{}
	for _, node := range cfg.Cluster.Nodes {
		nodeID := strings.TrimSpace(node.ID)
		if nodeID == "" {
			continue
		}
		seen[nodeID] = struct{}{}
		nodes = append(nodes, runtimeNodeFromConfig(cfg, node, records[nodeID], now, ttl, lang))
	}
	localID := strings.TrimSpace(cfg.Cluster.NodeID)
	if localID != "" {
		if _, ok := seen[localID]; !ok {
			nodes = append(nodes, runtimeNodeFromConfig(cfg, config.ClusterNodeConfig{
				ID:            localID,
				Role:          "waf",
				AdvertiseAddr: cfg.Cluster.Interconnect.AdvertiseAddr,
			}, records[localID], now, ttl, lang))
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		return nodes[i].NodeID < nodes[j].NodeID
	})
	return nodes
}

func runtimeNodeFromConfig(cfg *config.Config, node config.ClusterNodeConfig, heartbeat Heartbeat, now time.Time, ttl time.Duration, lang string) RuntimeNodeStatus {
	role := strings.TrimSpace(node.Role)
	if role == "" {
		role = "waf"
	}
	status := RuntimeNodeStatus{
		NodeID:        strings.TrimSpace(node.ID),
		Role:          role,
		AdvertiseAddr: strings.TrimSpace(node.AdvertiseAddr),
		Region:        strings.TrimSpace(node.Region),
		Datacenter:    strings.TrimSpace(node.Datacenter),
		State:         NodeStateUnknown,
		Local:         strings.TrimSpace(cfg.Cluster.NodeID) != "" && strings.TrimSpace(cfg.Cluster.NodeID) == strings.TrimSpace(node.ID),
		Reason:        label(lang, "等待节点心跳", "Waiting for node heartbeat"),
	}
	if status.AdvertiseAddr == "" && status.Local {
		status.AdvertiseAddr = strings.TrimSpace(cfg.Cluster.Interconnect.AdvertiseAddr)
	}
	if status.Local && heartbeat.RecordedAt.IsZero() {
		status.State = NodeStateOnline
		status.CanReceiveTraffic = role == "waf"
		status.CanWriteConfig = true
		status.Reason = label(lang, "本机节点", "Local node")
		return status
	}
	if heartbeat.RecordedAt.IsZero() {
		status.CanReceiveTraffic = false
		status.CanWriteConfig = false
		return status
	}
	recordedAt := heartbeat.RecordedAt.UTC()
	status.LastHeartbeatAt = &recordedAt
	if now.After(recordedAt) {
		status.LastSeenAgoSeconds = int64(now.Sub(recordedAt).Seconds())
	}
	if heartbeat.Role != "" {
		status.Role = heartbeat.Role
	}
	if heartbeat.AdvertiseAddr != "" {
		status.AdvertiseAddr = heartbeat.AdvertiseAddr
	}
	status.ConfigVersion = heartbeat.ConfigVersion
	if now.Sub(recordedAt) > ttl {
		status.State = NodeStateStale
		status.CanReceiveTraffic = false
		status.CanWriteConfig = false
		status.Reason = label(lang, "节点心跳超时", "Node heartbeat timed out")
		return status
	}
	status.State = NodeStateOnline
	status.CanReceiveTraffic = role == "waf"
	if heartbeat.CanReceiveTrafficSet {
		status.CanReceiveTraffic = heartbeat.CanReceiveTraffic
	}
	status.CanWriteConfig = true
	if heartbeat.CanWriteConfigSet {
		status.CanWriteConfig = heartbeat.CanWriteConfig
	}
	status.Reason = ""
	return status
}

func onlineVotingNodeCount(nodes []RuntimeNodeStatus) int {
	count := 0
	for _, node := range nodes {
		if !isVotingRole(node.Role) {
			continue
		}
		if node.State == NodeStateOnline && node.CanWriteConfig {
			count++
		}
	}
	return count
}

func votingNodeCount(nodes []RuntimeNodeStatus) int {
	count := 0
	for _, node := range nodes {
		if isVotingRole(node.Role) {
			count++
		}
	}
	return count
}

func isVotingRole(role string) bool {
	switch strings.TrimSpace(role) {
	case "waf", "monitor":
		return true
	default:
		return false
	}
}
