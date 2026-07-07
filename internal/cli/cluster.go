package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
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
	cmd.AddCommand(newClusterTokenCommand())
	cmd.AddCommand(&cobra.Command{
		Use:   "monitor-node",
		Short: "Run as a cluster monitor node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("monitor node runtime is not enabled before cluster initialization")
		},
	})
	return cmd
}

func newClusterTokenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage one-time cluster join tokens",
	}
	cmd.AddCommand(newClusterTokenCreateCommand())
	cmd.AddCommand(newClusterTokenListCommand())
	cmd.AddCommand(newClusterTokenRevokeCommand())
	return cmd
}

func newClusterTokenCreateCommand() *cobra.Command {
	var role string
	var ttl string
	var uses int
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a one-time cluster join token",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, svc, err := clusterIdentityFromCLI()
			if err != nil {
				return err
			}
			duration := cfg.Cluster.Join.TokenTTL
			if strings.TrimSpace(ttl) != "" {
				duration, err = time.ParseDuration(strings.TrimSpace(ttl))
				if err != nil {
					return fmt.Errorf("ttl must be a duration such as 15m: %w", err)
				}
			}
			if duration == 0 {
				duration = 15 * time.Minute
			}
			if uses == 0 {
				uses = 1
			}
			token, err := svc.CreateJoinToken(role, duration, uses)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "令牌ID: %s\n", token.ID)
			fmt.Fprintf(out, "加入令牌: %s\n", token.Value)
			fmt.Fprintf(out, "角色: %s\n", roleLabel(token.Role))
			fmt.Fprintf(out, "有效期至: %s\n", token.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintln(out, "请立即保存加入令牌；CheeseWAF 只保存哈希，之后不会再次显示明文。")
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "waf", "Node role: waf or monitor")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Token lifetime, for example 15m")
	cmd.Flags().IntVar(&uses, "uses", 1, "Maximum token uses")
	return cmd
}

func newClusterTokenListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored cluster join tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, svc, err := clusterIdentityFromCLI()
			if err != nil {
				return err
			}
			tokens := svc.ListJoinTokens()
			out := cmd.OutOrStdout()
			if len(tokens) == 0 {
				fmt.Fprintln(out, "暂无加入令牌")
				return nil
			}
			for _, token := range tokens {
				state := "可用"
				if token.Revoked {
					state = "已撤销"
				} else if token.UsedCount >= token.MaxUses {
					state = "已用完"
				} else if !time.Now().UTC().Before(token.ExpiresAt) {
					state = "已过期"
				}
				fmt.Fprintf(out, "%s\t%s\t%s\t%d/%d\t%s\n", token.ID, roleLabel(token.Role), state, token.UsedCount, token.MaxUses, token.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}
}

func newClusterTokenRevokeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke TOKEN_ID",
		Short: "Revoke a cluster join token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, svc, err := clusterIdentityFromCLI()
			if err != nil {
				return err
			}
			id := strings.TrimSpace(args[0])
			if err := svc.RevokeJoinToken(id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已撤销加入令牌: %s\n", id)
			return nil
		},
	}
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

func clusterIdentityFromCLI() (*config.Config, *identity.MemoryIdentityService, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	clusterID := strings.TrimSpace(cfg.Cluster.ClusterID)
	if clusterID == "" {
		clusterID = "cheesewaf-local"
	}
	statePath := filepath.Join(dataDir, "cluster", "identity.json")
	svc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		ClusterID: clusterID,
		StatePath: statePath,
	})
	if err != nil {
		return nil, nil, err
	}
	return cfg, svc, nil
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
