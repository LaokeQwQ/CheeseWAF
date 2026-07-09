package cluster

import (
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Status struct {
	Mode                 string `json:"mode"`
	Enabled              bool   `json:"enabled"`
	ClusterID            string `json:"cluster_id,omitempty"`
	NodeID               string `json:"node_id,omitempty"`
	ProductModeLabel     string `json:"product_mode_label"`
	CanWriteConfig       bool   `json:"can_write_config"`
	CanReceiveTraffic    bool   `json:"can_receive_traffic"`
	MajorityConfirmed    bool   `json:"majority_confirmed"`
	NodeCount            int    `json:"node_count"`
	WAFNodeCount         int    `json:"waf_node_count"`
	MonitorNodeCount     int    `json:"monitor_node_count"`
	OnlineNodeCount      int    `json:"online_node_count"`
	OnlineVotingCount    int    `json:"online_voting_count"`
	VotingNodeCount      int    `json:"voting_node_count"`
	ConsensusProvider    string `json:"consensus_provider"`
	ProtectionModeReason string `json:"protection_mode_reason,omitempty"`
}

func FromConfig(cfg *config.Config, lang string) Status {
	return FromConfigWithRuntime(cfg, nil, lang)
}

func FromConfigWithRuntime(cfg *config.Config, registry *HeartbeatRegistry, lang string) Status {
	if cfg == nil {
		return standaloneStatus(lang)
	}
	if !cfg.Cluster.Enabled || cfg.Deployment.Mode != "cluster" {
		status := standaloneStatus(lang)
		status.ConsensusProvider = defaultConsensusProvider(cfg.Cluster.Consensus.Provider)
		return status
	}
	mode := strings.TrimSpace(cfg.Cluster.HAMode)
	if mode == "" {
		mode = "single-node"
	}
	status := Status{
		Mode:              mode,
		Enabled:           true,
		ClusterID:         cfg.Cluster.ClusterID,
		NodeID:            cfg.Cluster.NodeID,
		CanWriteConfig:    true,
		CanReceiveTraffic: true,
		NodeCount:         len(cfg.Cluster.Nodes),
		ConsensusProvider: defaultConsensusProvider(cfg.Cluster.Consensus.Provider),
	}
	for _, node := range cfg.Cluster.Nodes {
		switch node.Role {
		case "waf":
			status.WAFNodeCount++
		case "monitor":
			status.MonitorNodeCount++
		}
	}
	nodes := RuntimeNodes(cfg, registry, lang)
	status.NodeCount = len(nodes)
	status.VotingNodeCount = votingNodeCount(nodes)
	status.OnlineVotingCount = onlineVotingNodeCount(nodes)
	for _, node := range nodes {
		if node.State == NodeStateOnline {
			status.OnlineNodeCount++
		}
	}
	status.MajorityConfirmed = majorityConfirmed(mode, status.VotingNodeCount, status.OnlineVotingCount)
	if mode == "minimum-ha" || mode == "multi-node-ha" {
		if !status.MajorityConfirmed {
			if cfg.Cluster.Protection.FreezeWritesWithoutMajority {
				status.CanWriteConfig = false
			}
			if !cfg.Cluster.Protection.AllowTrafficInProtectionMode {
				status.CanReceiveTraffic = false
			}
			status.ProtectionModeReason = label(lang, "等待多数节点心跳确认后允许配置变更", "Waiting for majority node heartbeats before allowing configuration writes")
		}
	}
	status.ProductModeLabel = ModeLabel(mode, lang)
	return status
}

func ModeLabel(mode, lang string) string {
	zh := strings.HasPrefix(lang, "zh")
	switch mode {
	case "single-node", "standalone":
		return labelByBool(zh, "单机模式", "Standalone")
	case "dual-node-load-balancing":
		return labelByBool(zh, "双节点负载均衡", "Dual-node load balancing")
	case "minimum-ha":
		return labelByBool(zh, "最小高可用", "Minimum HA")
	case "multi-node-ha":
		return labelByBool(zh, "多节点高可用", "Multi-node HA")
	case "protection":
		return labelByBool(zh, "保护模式", "Protection mode")
	default:
		return labelByBool(zh, "初始化中", "Initializing")
	}
}

func standaloneStatus(lang string) Status {
	return Status{
		Mode:              "standalone",
		Enabled:           false,
		ProductModeLabel:  ModeLabel("standalone", lang),
		CanWriteConfig:    true,
		CanReceiveTraffic: true,
		MajorityConfirmed: true,
		ConsensusProvider: "builtin",
	}
}

func defaultConsensusProvider(provider string) string {
	if strings.TrimSpace(provider) == "" {
		return "builtin"
	}
	return provider
}

func majorityConfirmed(mode string, voters int, online int) bool {
	mode = strings.TrimSpace(mode)
	if mode == "" || mode == "single-node" || mode == "standalone" || mode == "dual-node-load-balancing" {
		return true
	}
	if voters <= 1 {
		return true
	}
	required := voters/2 + 1
	return online >= required
}

func label(lang, zh, en string) string {
	return labelByBool(strings.HasPrefix(lang, "zh"), zh, en)
}

func labelByBool(zh bool, zhText, enText string) string {
	if zh {
		return zhText
	}
	return enText
}
