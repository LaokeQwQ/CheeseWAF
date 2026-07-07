package cli

import (
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	clusterobject "github.com/LaokeQwQ/CheeseWAF/internal/cluster/object"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage CheeseWAF cluster",
	}
	cmd.AddCommand(newClusterStatusCommand())
	cmd.AddCommand(newClusterInitCommand())
	cmd.AddCommand(newClusterExportCommand())
	cmd.AddCommand(&cobra.Command{
		Use:   "monitor-node",
		Short: "Run as a cluster monitor node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("monitor node runtime is not enabled before cluster initialization")
		},
	})
	return cmd
}

func newClusterStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show cluster status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			status := cluster.FromConfig(cfg, "zh-CN")
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "运行模式: %s\n", status.ProductModeLabel)
			fmt.Fprintf(out, "集群状态: %s\n", enabledLabel(status.Enabled))
			fmt.Fprintf(out, "配置变更: %s\n", allowedLabel(status.CanWriteConfig))
			fmt.Fprintf(out, "流量接收: %s\n", allowedLabel(status.CanReceiveTraffic))
			fmt.Fprintf(out, "多数确认: %s\n", confirmedLabel(status.MajorityConfirmed))
			if status.NodeCount > 0 {
				fmt.Fprintf(out, "节点数量: %d (WAF %d / 监控节点 %d)\n", status.NodeCount, status.WAFNodeCount, status.MonitorNodeCount)
			}
			if status.ProtectionModeReason != "" {
				fmt.Fprintf(out, "保护原因: %s\n", status.ProtectionModeReason)
			}
			return nil
		},
	}
}

func newClusterInitCommand() *cobra.Command {
	var opts clusterInitOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize this node as a single-node cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterInit(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.ClusterID, "cluster-id", "cheesewaf-local", "Cluster identifier")
	cmd.Flags().StringVar(&opts.NodeID, "node-id", "waf-local", "Current node identifier")
	cmd.Flags().StringVar(&opts.AdvertiseAddr, "advertise-addr", "127.0.0.1:9444", "Node interconnect address")
	cmd.Flags().StringVar(&opts.Listen, "listen", "127.0.0.1:9444", "Node interconnect listen address")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "Overwrite existing cluster configuration")
	return cmd
}

func newClusterExportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export current cluster declarative objects",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			objects, err := clusterObjectsFromConfig(cfg)
			if err != nil {
				return err
			}
			data, err := yaml.Marshal(map[string]any{
				"apiVersion": clusterobject.APIVersionV1,
				"kind":       "ClusterObjectList",
				"items":      objects,
			})
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

type clusterInitOptions struct {
	ClusterID     string
	NodeID        string
	AdvertiseAddr string
	Listen        string
	Force         bool
}

func runClusterInit(cmd *cobra.Command, opts clusterInitOptions) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.Cluster.Enabled && !opts.Force {
		return fmt.Errorf("cluster is already enabled; use --force to rewrite this node's single-node cluster config")
	}
	clusterID := strings.TrimSpace(opts.ClusterID)
	nodeID := strings.TrimSpace(opts.NodeID)
	advertiseAddr := strings.TrimSpace(opts.AdvertiseAddr)
	listen := strings.TrimSpace(opts.Listen)
	if clusterID == "" {
		return fmt.Errorf("cluster-id is required")
	}
	if nodeID == "" {
		return fmt.Errorf("node-id is required")
	}
	if advertiseAddr == "" {
		return fmt.Errorf("advertise-addr is required")
	}
	if listen == "" {
		listen = advertiseAddr
	}

	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = clusterID
	cfg.Cluster.NodeID = nodeID
	cfg.Cluster.HAMode = "single-node"
	cfg.Cluster.Interconnect.Listen = listen
	cfg.Cluster.Interconnect.AdvertiseAddr = advertiseAddr
	cfg.Cluster.Interconnect.MTLSRequired = true
	cfg.Cluster.Consensus.Provider = "builtin"
	cfg.Cluster.Join.RequireApproval = true
	if cfg.Cluster.Join.TokenTTL == 0 {
		cfg.Cluster.Join.TokenTTL = config.Default().Cluster.Join.TokenTTL
	}
	cfg.Cluster.Protection.FreezeWritesWithoutMajority = true
	cfg.Cluster.Protection.AllowTrafficInProtectionMode = true
	cfg.Cluster.Nodes = []config.ClusterNodeConfig{{
		ID:            nodeID,
		Role:          "waf",
		AdvertiseAddr: advertiseAddr,
	}}

	if err := config.Validate(cfg); err != nil {
		return err
	}
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "已初始化为单节点集群: %s / %s\n", clusterID, nodeID)
	fmt.Fprintln(cmd.OutOrStdout(), "当前仍是单节点模式；M2 部署加入流程完成后可扩展更多机器。")
	return nil
}

func clusterObjectsFromConfig(cfg *config.Config) ([]any, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	status := cluster.FromConfig(cfg, "zh-CN")
	policy, err := clusterobject.Normalize(clusterobject.Resource[clusterobject.ClusterPolicySpec, clusterobject.ClusterPolicyStatus]{
		APIVersion: clusterobject.APIVersionV1,
		Kind:       clusterobject.KindClusterPolicy,
		Metadata: clusterobject.Metadata{
			ID:   valueOrDefault(cfg.Cluster.ClusterID, "standalone"),
			Name: "CheeseWAF Cluster Policy",
			Labels: map[string]string{
				"产品状态": "M1",
				"保护能力": "防数据偏差",
			},
		},
		Spec: clusterobject.ClusterPolicySpec{
			HAMode:             valueOrDefault(cfg.Cluster.HAMode, "single-node"),
			ConsensusProvider:  valueOrDefault(cfg.Cluster.Consensus.Provider, "builtin"),
			AutoApprovalPolicy: "manual",
		},
		Status: clusterobject.ClusterPolicyStatus{
			Healthy:              status.CanReceiveTraffic,
			MajorityConfirmed:    status.MajorityConfirmed,
			ProtectionModeReason: status.ProtectionModeReason,
		},
	})
	if err != nil {
		return nil, err
	}
	items := []any{policy}
	for _, node := range cfg.Cluster.Nodes {
		res, err := clusterobject.Normalize(clusterobject.Resource[clusterobject.NodeSpec, clusterobject.NodeStatus]{
			APIVersion: clusterobject.APIVersionV1,
			Kind:       clusterobject.KindNode,
			Metadata: clusterobject.Metadata{
				ID:   node.ID,
				Name: node.ID,
				Labels: map[string]string{
					"节点角色": roleLabel(node.Role),
				},
			},
			Spec: clusterobject.NodeSpec{
				Role:          node.Role,
				AdvertiseAddr: node.AdvertiseAddr,
				Region:        node.Region,
				Datacenter:    node.Datacenter,
			},
			Status: clusterobject.NodeStatus{
				Mode:              status.Mode,
				CanReceiveTraffic: status.CanReceiveTraffic,
				CanWriteConfig:    status.CanWriteConfig,
				Reason:            status.ProtectionModeReason,
			},
		})
		if err != nil {
			return nil, err
		}
		items = append(items, res)
	}
	return items, nil
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func roleLabel(role string) string {
	if role == "monitor" {
		return "监控节点"
	}
	return "WAF 节点"
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "已启用"
	}
	return "未启用"
}

func allowedLabel(allowed bool) string {
	if allowed {
		return "允许"
	}
	return "暂停"
}

func confirmedLabel(ok bool) string {
	if ok {
		return "已确认"
	}
	return "未确认"
}
