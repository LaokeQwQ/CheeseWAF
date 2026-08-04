// Package consensus implements a lightweight built-in coordinator for M3.
// It is not a full Raft/etcd replica set: leadership is derived from live
// heartbeats and a stable node ordering so protection mode and config freezes
// have a single writable coordinator.
package consensus

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
)

const (
	ProviderBuiltin = "builtin"
	ProviderEtcd    = "etcd"

	RoleLeader   = "leader"
	RoleFollower = "follower"
	RoleObserver = "observer"
)

// ConfigVersionRecord is an append-only config change notice replicated in memory.
type ConfigVersionRecord struct {
	Version   string    `json:"version"`
	LeaderID  string    `json:"leader_id"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Snapshot is the coordinator view exposed to APIs and health checks.
type Snapshot struct {
	Provider          string                `json:"provider"`
	LeaderID          string                `json:"leader_id,omitempty"`
	LocalNodeID       string                `json:"local_node_id,omitempty"`
	LocalRole         string                `json:"local_role,omitempty"`
	Term              uint64                `json:"term"`
	MajorityConfirmed bool                  `json:"majority_confirmed"`
	CanWriteConfig    bool                  `json:"can_write_config"`
	OnlineVoters      int                   `json:"online_voters"`
	VotingNodes       int                   `json:"voting_nodes"`
	EtcdConfigured    bool                  `json:"etcd_configured"`
	EtcdEndpoints     []string              `json:"etcd_endpoints,omitempty"`
	RecentVersions    []ConfigVersionRecord `json:"recent_versions,omitempty"`
	Reason            string                `json:"reason,omitempty"`
}

// Coordinator owns leadership and a small in-memory config version log.
type Coordinator struct {
	mu       sync.RWMutex
	provider string
	localID  string
	etcd     []string
	term     uint64
	log      []ConfigVersionRecord
	maxLog   int
	now      func() time.Time
}

type Options struct {
	Provider      string
	LocalNodeID   string
	EtcdEndpoints []string
	MaxLog        int
	Now           func() time.Time
}

func NewCoordinator(opts Options) *Coordinator {
	provider := strings.TrimSpace(strings.ToLower(opts.Provider))
	if provider == "" {
		provider = ProviderBuiltin
	}
	maxLog := opts.MaxLog
	if maxLog <= 0 {
		maxLog = 32
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Coordinator{
		provider: provider,
		localID:  strings.TrimSpace(opts.LocalNodeID),
		etcd:     append([]string(nil), opts.EtcdEndpoints...),
		maxLog:   maxLog,
		now:      now,
	}
}

// Evaluate derives leadership from online voting nodes (lowest node ID wins).
func (c *Coordinator) Evaluate(status cluster.Status, nodes []cluster.RuntimeNodeStatus) Snapshot {
	if c == nil {
		return Snapshot{Provider: ProviderBuiltin, MajorityConfirmed: true, CanWriteConfig: true}
	}
	c.mu.RLock()
	provider := c.provider
	localID := c.localID
	term := c.term
	etcd := append([]string(nil), c.etcd...)
	logCopy := append([]ConfigVersionRecord(nil), c.log...)
	c.mu.RUnlock()

	snap := Snapshot{
		Provider:          provider,
		LocalNodeID:       localID,
		Term:              term,
		MajorityConfirmed: status.MajorityConfirmed,
		CanWriteConfig:    status.CanWriteConfig,
		OnlineVoters:      status.OnlineVotingCount,
		VotingNodes:       status.VotingNodeCount,
		EtcdConfigured:    provider == ProviderEtcd && len(etcd) > 0,
		EtcdEndpoints:     etcd,
		RecentVersions:    logCopy,
		Reason:            status.ProtectionModeReason,
	}

	voters := onlineVotingIDs(nodes)
	if len(voters) == 0 {
		if localID != "" {
			snap.LeaderID = localID
			snap.LocalRole = RoleLeader
		}
		return snap
	}
	sort.Strings(voters)
	leader := voters[0]
	snap.LeaderID = leader
	switch {
	case localID == "":
		snap.LocalRole = RoleObserver
	case localID == leader:
		snap.LocalRole = RoleLeader
	default:
		// Non-voting monitors are observers; voting followers remain followers.
		if isVotingNode(nodes, localID) {
			snap.LocalRole = RoleFollower
		} else {
			snap.LocalRole = RoleObserver
		}
	}
	if provider == ProviderEtcd && !snap.EtcdConfigured {
		snap.Reason = "etcd provider selected but no endpoints configured; operating on builtin heartbeat majority only"
	}
	return snap
}

// ProposeConfigVersion appends a version record when the local node is allowed to write.
func (c *Coordinator) ProposeConfigVersion(version, message string, status cluster.Status, nodes []cluster.RuntimeNodeStatus) (ConfigVersionRecord, error) {
	if c == nil {
		return ConfigVersionRecord{}, fmt.Errorf("consensus coordinator unavailable")
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return ConfigVersionRecord{}, fmt.Errorf("config version is required")
	}
	snap := c.Evaluate(status, nodes)
	if !snap.CanWriteConfig {
		return ConfigVersionRecord{}, fmt.Errorf("config writes are frozen: %s", strings.TrimSpace(snap.Reason))
	}
	if strings.TrimSpace(snap.LocalNodeID) == "" {
		return ConfigVersionRecord{}, fmt.Errorf("local node id is required to propose config versions")
	}
	if snap.LocalRole != RoleLeader {
		return ConfigVersionRecord{}, fmt.Errorf("only the cluster leader may propose config versions (leader=%s role=%s)", snap.LeaderID, snap.LocalRole)
	}
	rec := ConfigVersionRecord{
		Version:   version,
		LeaderID:  snap.LeaderID,
		Message:   strings.TrimSpace(message),
		CreatedAt: c.now().UTC(),
	}
	if rec.LeaderID == "" {
		rec.LeaderID = c.localID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.term++
	rec.LeaderID = firstNonEmpty(rec.LeaderID, c.localID)
	c.log = append(c.log, rec)
	if len(c.log) > c.maxLog {
		c.log = append([]ConfigVersionRecord(nil), c.log[len(c.log)-c.maxLog:]...)
	}
	return rec, nil
}

func (c *Coordinator) SetProvider(provider string, etcd []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	provider = strings.TrimSpace(strings.ToLower(provider))
	if provider == "" {
		provider = ProviderBuiltin
	}
	c.provider = provider
	c.etcd = append([]string(nil), etcd...)
}

func onlineVotingIDs(nodes []cluster.RuntimeNodeStatus) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		// Match majority counting: voting role, online, and still able to write config.
		if node.State != cluster.NodeStateOnline || !node.CanWriteConfig {
			continue
		}
		if !isVotingRole(node.Role) {
			continue
		}
		out = append(out, node.NodeID)
	}
	return out
}

func isVotingNode(nodes []cluster.RuntimeNodeStatus, nodeID string) bool {
	for _, node := range nodes {
		if node.NodeID == nodeID {
			return isVotingRole(node.Role)
		}
	}
	return false
}

func isVotingRole(role string) bool {
	switch strings.TrimSpace(role) {
	case "waf", "monitor":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
