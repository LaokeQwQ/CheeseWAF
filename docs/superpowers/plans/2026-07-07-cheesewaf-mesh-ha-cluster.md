# CheeseWAF Mesh HA Cluster Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build CheeseWAF from default single-node operation into a product-grade, single-Go-binary Mesh HA cluster with built-in deployment, node coordination, data consistency, and production traffic scheduling.

**Architecture:** CheeseWAF keeps standalone mode as the default. A standalone node can expand into a cluster through the Web console, CLI, or generated Ansible package. Cluster mode uses a declarative object model, mTLS node identity, one-time join tokens, built-in Raft by default, optional external etcd, local SQLite as cache/buffer, and a built-in production traffic scheduler.

**Tech Stack:** Go, cobra CLI, chi API handlers, YAML/JSON object manifests, SQLite local cache, built-in Raft/DCS module, optional etcd adapter, mTLS using Go crypto/tls, React/TypeScript Web console, Ansible package generation.

---

## Product Decisions

- Default mode is **single-node mode**.
- The Web console adds a **Cluster** menu, but single-node installs remain fully usable.
- Two WAF nodes are **dual-node load-balancing mode**, not full HA. If node interconnect fails, the cluster enters **protection mode** and pauses configuration writes.
- Two WAF nodes plus one **monitor node** form the smallest HA mode.
- Three or more WAF nodes form multi-node HA mode.
- The monitor node uses the same Go binary and productized command: `cheesewaf cluster monitor-node`.
- Default cluster consistency uses built-in Raft. External etcd is an advanced option.
- Node-to-node traffic uses mTLS and one-time join tokens.
- Configuration is stored as declarative objects and reconciled into the existing runtime config.
- SQLite remains the single-node store. In cluster mode it becomes a local cache, local event buffer, and emergency recovery source.
- Logs and security events use local buffering plus central aggregation. Central storage failure must not block WAF traffic.
- Every WAF node can open the console. Write operations require cluster majority confirmation.
- AI self-learning and automatic rule application use configurable approval policies. Default is manual approval.
- The built-in traffic scheduler is product-grade and should aim to replace a professional LB for common deployments, while still supporting external LB integration.

## Product Language

Use product wording in UI and docs:

- `split-brain` / 防脑裂 -> **数据分歧** / **防数据偏差**
- `witness` -> **监控节点**
- `quorum` -> **多数确认**
- `leader` -> **协调节点**
- `fencing` -> **节点隔离**
- `DCS` -> **集群一致性服务**
- `dry-run` -> **仅检查不应用**
- `preflight` -> **部署前检查** / **升级前检查**
- `schema` -> **配置结构版本**
- `dev` -> **开发版**
- `canary` -> **预览版**
- `stable` -> **正式版**
- `ready` -> **可接收流量**
- `drain` -> **暂停接收新流量**

## Target File Structure

### Backend Cluster Core

- Create: `internal/cluster/config.go`
  - Cluster configuration structs and validation helpers.
- Create: `internal/cluster/object/object.go`
  - Declarative resource envelope: `apiVersion`, `kind`, `metadata`, `spec`, `status`.
- Create: `internal/cluster/object/node.go`
  - Node object spec/status.
- Create: `internal/cluster/object/token.go`
  - Join token object spec/status.
- Create: `internal/cluster/object/cert.go`
  - Cluster certificate and node certificate objects.
- Create: `internal/cluster/object/policy.go`
  - Cluster policy, approval policy, and protection-mode policy objects.
- Create: `internal/cluster/store/store.go`
  - Object store interface for standalone, Raft, and etcd-backed stores.
- Create: `internal/cluster/store/standalone.go`
  - Single-node object store for M1.
- Create: `internal/cluster/reconcile/reconciler.go`
  - Converts cluster objects to current runtime config and reports status.
- Create: `internal/cluster/deploy/ansible.go`
  - Generates an Ansible package from inventory and cluster choices.
- Create: `internal/cluster/deploy/ssh.go`
  - Temporary SSH deployment runner with no long-term credential persistence by default.
- Create: `internal/cluster/identity/pki.go`
  - Cluster CA, join token signing, node certificate issuance, rotation, and revocation.
- Create: `internal/cluster/health/health.go`
  - Node health model used by API, CLI, and scheduler.
- Create: `internal/cluster/consensus/raft.go`
  - Built-in Raft adapter for M3.
- Create: `internal/cluster/consensus/etcd.go`
  - External etcd adapter for M3.
- Create: `internal/cluster/scheduler/scheduler.go`
  - Product-grade traffic scheduler for M4.

### Backend Integration

- Modify: `internal/config/config.go`
  - Add `Deployment DeploymentConfig` and `Cluster cluster.Config`.
- Modify: `internal/config/validator.go`
  - Validate cluster mode, ports, join token TTL, node roles, external etcd URLs, and unsafe combinations.
- Modify: `configs/cheesewaf.yaml`
  - Add disabled-by-default cluster config examples with product wording.
- Modify: `internal/api/router.go`
  - Add authenticated cluster API routes and RBAC permissions.
- Create: `internal/api/handler/cluster.go`
  - Cluster status, init, join token, inventory, deployment, node health, object export/import.
- Create: `internal/api/handler/cluster_test.go`
  - API coverage.
- Modify: `internal/cli/root.go`
  - Register `cluster` command group.
- Create: `internal/cli/cluster.go`
  - `cluster status`, `init`, `export`, `import`, `apply`, `diff`, `rollback`, `monitor-node`.
- Create: `internal/cli/cluster_test.go`
  - CLI coverage.
- Modify: `internal/cli/service.go`
  - Start cluster services only when cluster mode is enabled.
- Modify: `internal/api/handler/monitor.go`
  - Include cluster health summary in monitor snapshot.
- Modify: `internal/ai/self_learning.go`
  - Use global task lock and approval policy before applying cluster-wide changes.

### Web Console

- Create: `web/src/pages/Cluster/ClusterPage.tsx`
  - Cluster status page, single-node expansion entry, node table, protection mode banner.
- Create: `web/src/pages/Cluster/ClusterWizard.tsx`
  - Wizard: deployment method, hosts, deployment checks, plan, execute/export, result.
- Create: `web/src/pages/Cluster/ClusterObjects.tsx`
  - Export/import/diff/rollback object UI.
- Create: `web/src/pages/Cluster/ClusterTokens.tsx`
  - Join token and node certificate management.
- Create: `web/src/pages/Cluster/ClusterUpgrade.tsx`
  - Upgrade checks, rolling upgrade, rollback UI.
- Create: `web/src/pages/Cluster/ClusterTraffic.tsx`
  - Built-in traffic scheduling policy UI.
- Modify: `web/src/api/client.ts`
  - Add cluster API client methods.
- Modify: `web/src/types/api.ts`
  - Add cluster DTOs.
- Modify: `web/src/layouts/MainLayout.tsx`
  - Add Cluster navigation entry.
- Modify: `web/src/i18n/locales/zh-CN.ts`
  - Add productized Chinese labels.
- Modify: `web/src/i18n/locales/en-US.ts`
  - Add English labels.
- Modify: `web/src/styles/global.css`
  - Add stable responsive layout for cluster pages.

### Docs And Packaging

- Modify: `implementation_plan.md`
  - Add Mesh HA cluster roadmap.
- Modify: `task.md`
  - Add M1-M4 checklist.
- Modify: `progress.md`
  - Add public-facing roadmap summary without secrets.
- Create: `docs/cluster-ha.md`
  - Public cluster design and operations guide.
- Create: `deploy/ansible/cheesewaf-cluster/README.md`
  - Generated-package format and manual execution guide.

---

## M1: Cluster Planning And Declarative Object Model

### Task 1: Add Disabled-By-Default Cluster Config

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/validator.go`
- Modify: `configs/cheesewaf.yaml`
- Test: `internal/config/cluster_test.go`

- [ ] **Step 1: Write failing config tests**

Create `internal/config/cluster_test.go`:

```go
package config

import "testing"

func TestClusterDefaultIsStandalone(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Deployment.Mode != "standalone" {
		t.Fatalf("default deployment mode = %q, want standalone", cfg.Deployment.Mode)
	}
	if cfg.Cluster.Enabled {
		t.Fatal("cluster must be disabled by default")
	}
}

func TestClusterRejectsUnsafeTwoNodeHAClaim(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.Nodes = []ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
	}
	cfg.Cluster.HAMode = "multi-node-ha"
	if err := Validate(&cfg); err == nil {
		t.Fatal("two WAF nodes must not validate as multi-node HA without a monitor node")
	}
}

func TestClusterAcceptsTwoWAFNodesWithMonitorNode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.HAMode = "minimum-ha"
	cfg.Cluster.Nodes = []ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
		{ID: "waf-b", Role: "waf", AdvertiseAddr: "10.0.0.2:9444"},
		{ID: "monitor-a", Role: "monitor", AdvertiseAddr: "10.0.0.3:9444"},
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid minimum HA cluster rejected: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests and confirm failure**

Run:

```powershell
go test ./internal/config -run Cluster -count=1
```

Expected: fails because `DeploymentConfig`, `ClusterConfig`, and `DefaultConfig` fields do not exist.

- [ ] **Step 3: Implement config structs and defaults**

Add these types near the top-level config types in `internal/config/config.go`:

```go
type DeploymentConfig struct {
	Mode string `yaml:"mode" json:"mode"`
}

type ClusterConfig struct {
	Enabled       bool                `yaml:"enabled" json:"enabled"`
	ClusterID     string              `yaml:"cluster_id" json:"cluster_id"`
	NodeID        string              `yaml:"node_id" json:"node_id"`
	HAMode        string              `yaml:"ha_mode" json:"ha_mode"`
	Interconnect  InterconnectConfig  `yaml:"interconnect" json:"interconnect"`
	Consensus     ConsensusConfig     `yaml:"consensus" json:"consensus"`
	Join          JoinConfig          `yaml:"join" json:"join"`
	Nodes         []ClusterNodeConfig `yaml:"nodes" json:"nodes"`
	Protection    ClusterProtectionConfig `yaml:"protection" json:"protection"`
}

type InterconnectConfig struct {
	Listen        string `yaml:"listen" json:"listen"`
	AdvertiseAddr string `yaml:"advertise_addr" json:"advertise_addr"`
	MTLSRequired bool   `yaml:"mtls_required" json:"mtls_required"`
}

type ConsensusConfig struct {
	Provider string   `yaml:"provider" json:"provider"`
	EtcdEndpoints []string `yaml:"etcd_endpoints" json:"etcd_endpoints"`
}

type JoinConfig struct {
	RequireApproval bool   `yaml:"require_approval" json:"require_approval"`
	TokenTTL        string `yaml:"token_ttl" json:"token_ttl"`
}

type ClusterNodeConfig struct {
	ID            string `yaml:"id" json:"id"`
	Role          string `yaml:"role" json:"role"`
	AdvertiseAddr string `yaml:"advertise_addr" json:"advertise_addr"`
	Region        string `yaml:"region" json:"region"`
	Datacenter    string `yaml:"datacenter" json:"datacenter"`
}

type ClusterProtectionConfig struct {
	FreezeWritesWithoutMajority bool `yaml:"freeze_writes_without_majority" json:"freeze_writes_without_majority"`
	AllowTrafficInProtectionMode bool `yaml:"allow_traffic_in_protection_mode" json:"allow_traffic_in_protection_mode"`
}
```

Add fields to `Config`:

```go
Deployment DeploymentConfig `yaml:"deployment" json:"deployment"`
Cluster    ClusterConfig    `yaml:"cluster" json:"cluster"`
```

Set defaults in the existing default-config path:

```go
Deployment: DeploymentConfig{Mode: "standalone"},
Cluster: ClusterConfig{
	Enabled: false,
	HAMode: "single-node",
	Interconnect: InterconnectConfig{
		Listen: "127.0.0.1:9444",
		MTLSRequired: true,
	},
	Consensus: ConsensusConfig{Provider: "builtin"},
	Join: JoinConfig{RequireApproval: true, TokenTTL: "15m"},
	Protection: ClusterProtectionConfig{
		FreezeWritesWithoutMajority: true,
		AllowTrafficInProtectionMode: true,
	},
},
```

- [ ] **Step 4: Add validation**

Implement validation in `internal/config/validator.go`:

```go
func validateCluster(cfg *Config) error {
	mode := strings.TrimSpace(cfg.Deployment.Mode)
	if mode == "" {
		cfg.Deployment.Mode = "standalone"
		mode = "standalone"
	}
	if mode != "standalone" && mode != "cluster" {
		return fmt.Errorf("deployment.mode must be standalone or cluster")
	}
	if mode == "standalone" && cfg.Cluster.Enabled {
		return fmt.Errorf("cluster.enabled requires deployment.mode=cluster")
	}
	if mode == "standalone" {
		return nil
	}
	if cfg.Cluster.Consensus.Provider == "" {
		cfg.Cluster.Consensus.Provider = "builtin"
	}
	if cfg.Cluster.Consensus.Provider != "builtin" && cfg.Cluster.Consensus.Provider != "etcd" {
		return fmt.Errorf("cluster.consensus.provider must be builtin or etcd")
	}
	wafNodes := 0
	monitorNodes := 0
	seen := map[string]struct{}{}
	for _, node := range cfg.Cluster.Nodes {
		if strings.TrimSpace(node.ID) == "" {
			return fmt.Errorf("cluster node id is required")
		}
		if _, ok := seen[node.ID]; ok {
			return fmt.Errorf("duplicate cluster node id %q", node.ID)
		}
		seen[node.ID] = struct{}{}
		switch node.Role {
		case "waf":
			wafNodes++
		case "monitor":
			monitorNodes++
		default:
			return fmt.Errorf("cluster node %q role must be waf or monitor", node.ID)
		}
		if strings.TrimSpace(node.AdvertiseAddr) == "" {
			return fmt.Errorf("cluster node %q advertise_addr is required", node.ID)
		}
	}
	switch cfg.Cluster.HAMode {
	case "", "single-node", "dual-node-load-balancing":
		return nil
	case "minimum-ha":
		if wafNodes < 2 || monitorNodes < 1 {
			return fmt.Errorf("minimum-ha requires at least two WAF nodes and one monitor node")
		}
	case "multi-node-ha":
		if wafNodes < 3 {
			return fmt.Errorf("multi-node-ha requires at least three WAF nodes")
		}
	default:
		return fmt.Errorf("unknown cluster.ha_mode %q", cfg.Cluster.HAMode)
	}
	return nil
}
```

Call `validateCluster(cfg)` from the existing `Validate` flow.

- [ ] **Step 5: Run config tests**

Run:

```powershell
go test ./internal/config -run Cluster -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add internal/config/config.go internal/config/validator.go internal/config/cluster_test.go configs/cheesewaf.yaml
git commit -m "feat: add cluster deployment config model"
```

### Task 2: Add Declarative Cluster Object Model

**Files:**
- Create: `internal/cluster/object/object.go`
- Create: `internal/cluster/object/node.go`
- Create: `internal/cluster/object/policy.go`
- Create: `internal/cluster/object/token.go`
- Test: `internal/cluster/object/object_test.go`

- [ ] **Step 1: Write object envelope tests**

Create `internal/cluster/object/object_test.go`:

```go
package object

import "testing"

func TestResourceVersionChangesWhenSpecChanges(t *testing.T) {
	a := Resource[NodeSpec, NodeStatus]{
		APIVersion: "cluster.cheesewaf.io/v1",
		Kind: "Node",
		Metadata: Metadata{ID: "node-a", Generation: 1},
		Spec: NodeSpec{Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
	}
	b := a
	b.Spec.AdvertiseAddr = "10.0.0.2:9444"
	ha, err := HashSpec(a.Spec)
	if err != nil { t.Fatal(err) }
	hb, err := HashSpec(b.Spec)
	if err != nil { t.Fatal(err) }
	if ha == hb {
		t.Fatal("spec hash must change when spec changes")
	}
}

func TestNodeModeLabels(t *testing.T) {
	status := NodeStatus{Mode: "protection", CanReceiveTraffic: true, CanWriteConfig: false}
	if status.ProductModeLabel("zh-CN") != "保护模式" {
		t.Fatalf("unexpected zh label: %q", status.ProductModeLabel("zh-CN"))
	}
	if status.ProductModeLabel("en-US") != "Protection mode" {
		t.Fatalf("unexpected en label: %q", status.ProductModeLabel("en-US"))
	}
}
```

- [ ] **Step 2: Run tests and confirm failure**

```powershell
go test ./internal/cluster/object -count=1
```

Expected: package or symbols do not exist.

- [ ] **Step 3: Implement object envelope**

Create `internal/cluster/object/object.go`:

```go
package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Metadata struct {
	ID              string            `json:"id" yaml:"id"`
	Name            string            `json:"name,omitempty" yaml:"name,omitempty"`
	Labels          map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Owner           string            `json:"owner,omitempty" yaml:"owner,omitempty"`
	Generation      int64             `json:"generation" yaml:"generation"`
	ResourceVersion string            `json:"resource_version" yaml:"resource_version"`
	UpdatedAt       time.Time         `json:"updated_at" yaml:"updated_at"`
	LastAppliedHash string            `json:"last_applied_hash" yaml:"last_applied_hash"`
}

type Resource[S any, T any] struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       S        `json:"spec" yaml:"spec"`
	Status     T        `json:"status,omitempty" yaml:"status,omitempty"`
}

func HashSpec(spec any) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
```

- [ ] **Step 4: Implement node objects**

Create `internal/cluster/object/node.go`:

```go
package object

import "time"

type NodeSpec struct {
	Role          string `json:"role" yaml:"role"`
	AdvertiseAddr string `json:"advertise_addr" yaml:"advertise_addr"`
	Region        string `json:"region,omitempty" yaml:"region,omitempty"`
	Datacenter    string `json:"datacenter,omitempty" yaml:"datacenter,omitempty"`
	Weight        int    `json:"weight,omitempty" yaml:"weight,omitempty"`
}

type NodeStatus struct {
	Mode              string    `json:"mode" yaml:"mode"`
	CanReceiveTraffic bool      `json:"can_receive_traffic" yaml:"can_receive_traffic"`
	CanWriteConfig    bool      `json:"can_write_config" yaml:"can_write_config"`
	LastHeartbeatAt   time.Time `json:"last_heartbeat_at,omitempty" yaml:"last_heartbeat_at,omitempty"`
	ConfigVersion     string    `json:"config_version,omitempty" yaml:"config_version,omitempty"`
	Reason            string    `json:"reason,omitempty" yaml:"reason,omitempty"`
}

func (s NodeStatus) ProductModeLabel(lang string) string {
	switch s.Mode {
	case "protection":
		if lang == "zh-CN" || lang == "zh" {
			return "保护模式"
		}
		return "Protection mode"
	case "ready":
		if lang == "zh-CN" || lang == "zh" {
			return "可接收流量"
		}
		return "Ready for traffic"
	default:
		if lang == "zh-CN" || lang == "zh" {
			return "初始化中"
		}
		return "Initializing"
	}
}
```

- [ ] **Step 5: Implement policy and token objects**

Create `internal/cluster/object/policy.go`:

```go
package object

type ClusterPolicySpec struct {
	HAMode               string `json:"ha_mode" yaml:"ha_mode"`
	ConsensusProvider    string `json:"consensus_provider" yaml:"consensus_provider"`
	AutoApprovalPolicy   string `json:"auto_approval_policy" yaml:"auto_approval_policy"`
	MaxAutoChangesPerDay int    `json:"max_auto_changes_per_day" yaml:"max_auto_changes_per_day"`
}

type ClusterPolicyStatus struct {
	Healthy             bool   `json:"healthy" yaml:"healthy"`
	CurrentCoordinator  string `json:"current_coordinator,omitempty" yaml:"current_coordinator,omitempty"`
	MajorityConfirmed   bool   `json:"majority_confirmed" yaml:"majority_confirmed"`
	ProtectionModeReason string `json:"protection_mode_reason,omitempty" yaml:"protection_mode_reason,omitempty"`
}
```

Create `internal/cluster/object/token.go`:

```go
package object

import "time"

type JoinTokenSpec struct {
	TokenID   string    `json:"token_id" yaml:"token_id"`
	Role      string    `json:"role" yaml:"role"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`
	MaxUses   int       `json:"max_uses" yaml:"max_uses"`
}

type JoinTokenStatus struct {
	UsedCount int    `json:"used_count" yaml:"used_count"`
	Revoked   bool   `json:"revoked" yaml:"revoked"`
	Reason    string `json:"reason,omitempty" yaml:"reason,omitempty"`
}
```

- [ ] **Step 6: Run tests**

```powershell
go test ./internal/cluster/object -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add internal/cluster/object
git commit -m "feat: add cluster declarative objects"
```

### Task 3: Add Cluster CLI Skeleton With Real Standalone Status

**Files:**
- Modify: `internal/cli/root.go`
- Create: `internal/cli/cluster.go`
- Test: `internal/cli/cluster_test.go`

- [ ] **Step 1: Write CLI tests**

Create `internal/cli/cluster_test.go`:

```go
package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestClusterStatusShowsStandaloneByDefault(t *testing.T) {
	cmd := newRootCommand()
	buf := bytes.NewBuffer(nil)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"cluster", "status", "--config", testConfigPath(t)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cluster status failed: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "单机模式") && !strings.Contains(out, "Standalone") {
		t.Fatalf("cluster status did not show standalone mode: %s", out)
	}
}
```

- [ ] **Step 2: Run tests and confirm failure**

```powershell
go test ./internal/cli -run ClusterStatus -count=1
```

Expected: fails because cluster command does not exist.

- [ ] **Step 3: Implement CLI command**

Create `internal/cli/cluster.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "管理 CheeseWAF 集群",
	}
	cmd.AddCommand(newClusterStatusCommand())
	cmd.AddCommand(&cobra.Command{
		Use:   "monitor-node",
		Short: "以监控节点模式运行",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("监控节点运行时尚未启用，请先完成集群初始化")
		},
	})
	return cmd
}

func newClusterStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看集群状态",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "运行模式: 单机模式")
			fmt.Fprintln(cmd.OutOrStdout(), "集群状态: 未启用")
			fmt.Fprintln(cmd.OutOrStdout(), "说明: 可以在控制台的“集群”菜单中扩展为集群。")
			return nil
		},
	}
}
```

Register in `internal/cli/root.go`:

```go
rootCmd.AddCommand(newClusterCommand())
```

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cli -run ClusterStatus -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/cli/root.go internal/cli/cluster.go internal/cli/cluster_test.go
git commit -m "feat: add cluster cli status entry"
```

### Task 4: Add Web Cluster Menu And Standalone Status Page

**Files:**
- Create: `web/src/pages/Cluster/ClusterPage.tsx`
- Modify: `web/src/layouts/MainLayout.tsx`
- Modify: `web/src/api/client.ts`
- Modify: `web/src/types/api.ts`
- Modify: `web/src/i18n/locales/zh-CN.ts`
- Modify: `web/src/i18n/locales/en-US.ts`
- Test: `web` typecheck/build

- [ ] **Step 1: Add API type**

Add to `web/src/types/api.ts`:

```ts
export type ClusterStatus = {
  mode: 'standalone' | 'dual-node-load-balancing' | 'minimum-ha' | 'multi-node-ha';
  enabled: boolean;
  node_id: string;
  product_mode_label: string;
  can_write_config: boolean;
  can_receive_traffic: boolean;
  majority_confirmed: boolean;
  protection_mode_reason?: string;
};
```

- [ ] **Step 2: Add API client method**

Add to `web/src/api/client.ts`:

```ts
export async function getClusterStatus(): Promise<ClusterStatus> {
  return request<ClusterStatus>('/api/cluster/status');
}
```

- [ ] **Step 3: Add page**

Create `web/src/pages/Cluster/ClusterPage.tsx`:

```tsx
import { Button, Card, Spin, Typography } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import { getClusterStatus } from '../../api/client';
import { useI18n } from '../../i18n';

export default function ClusterPage() {
  const { t } = useI18n();
  const { data, isLoading } = useQuery({ queryKey: ['cluster-status'], queryFn: getClusterStatus });

  return (
    <main className="page-shell cluster-page">
      <section className="page-heading">
        <div>
          <Typography.Title heading={3}>{t('cluster.title')}</Typography.Title>
          <Typography.Paragraph>{t('cluster.subtitle')}</Typography.Paragraph>
        </div>
      </section>
      <Spin loading={isLoading && !data}>
        <Card className="cluster-status-card">
          <div className="cluster-status-main">
            <div>
              <span>{t('cluster.currentMode')}</span>
              <strong>{data?.product_mode_label || t('cluster.standalone')}</strong>
            </div>
            <div>
              <span>{t('cluster.configWrites')}</span>
              <strong>{data?.can_write_config ? t('cluster.allowed') : t('cluster.protected')}</strong>
            </div>
            <div>
              <span>{t('cluster.traffic')}</span>
              <strong>{data?.can_receive_traffic ? t('cluster.receiving') : t('cluster.notReceiving')}</strong>
            </div>
          </div>
          {!data?.enabled && (
            <div className="cluster-empty-action">
              <Typography.Paragraph>{t('cluster.singleNodeHint')}</Typography.Paragraph>
              <Button type="primary">{t('cluster.expand')}</Button>
            </div>
          )}
        </Card>
      </Spin>
    </main>
  );
}
```

- [ ] **Step 4: Add navigation and route**

Wire `ClusterPage` into the existing route mechanism and add nav item with label `cluster.title`.

- [ ] **Step 5: Add i18n**

Add Chinese:

```ts
cluster: {
  title: '集群',
  subtitle: '从单机扩展到多节点高可用，支持部署、节点状态和配置同步。',
  currentMode: '当前模式',
  standalone: '单机模式',
  configWrites: '配置变更',
  traffic: '流量接收',
  allowed: '允许',
  protected: '保护模式',
  receiving: '可接收流量',
  notReceiving: '暂停接收',
  singleNodeHint: '当前节点以单机模式运行。可以生成 Ansible 剧本，或由当前节点临时 SSH 部署更多机器。',
  expand: '扩展为集群',
}
```

Add English equivalents.

- [ ] **Step 6: Run Web checks**

```powershell
npm.cmd --prefix web run typecheck -- --pretty false
npm.cmd --prefix web run build
```

Expected: both pass.

- [ ] **Step 7: Commit**

```powershell
git add web/src/pages/Cluster web/src/layouts/MainLayout.tsx web/src/api/client.ts web/src/types/api.ts web/src/i18n/locales/zh-CN.ts web/src/i18n/locales/en-US.ts
git commit -m "feat: add cluster console entry"
```

---

## M2: Deployment And Join Flow

### Task 5: Generate Ansible Deployment Package

**Files:**
- Create: `internal/cluster/deploy/ansible.go`
- Create: `internal/cluster/deploy/ansible_test.go`
- Create: `deploy/ansible/cheesewaf-cluster/README.md`

- [ ] **Step 1: Write generation test**

```go
func TestGenerateAnsiblePackageIncludesInventoryAndNoSecrets(t *testing.T) {
	pkg, err := GenerateAnsiblePackage(Plan{
		ClusterID: "cw-test",
		Nodes: []Host{{Name: "waf-a", Address: "10.0.0.1", Role: "waf"}},
		Channel: "canary",
	})
	if err != nil { t.Fatal(err) }
	if !strings.Contains(string(pkg.File("inventory.ini")), "waf-a") {
		t.Fatal("inventory missing host")
	}
	if strings.Contains(string(pkg.File("group_vars/all.yml")), "password") {
		t.Fatal("generated package must not contain raw password")
	}
}
```

- [ ] **Step 2: Implement package generator**

Generate these files in memory:

```text
inventory.ini
group_vars/all.yml
playbook.yml
roles/cheesewaf/tasks/main.yml
roles/cheesewaf/templates/cheesewaf.yaml.j2
README.md
```

Use product names `开发版`, `预览版`, `正式版` in comments while keeping machine values `dev`, `canary`, `stable`.

- [ ] **Step 3: Run tests**

```powershell
go test ./internal/cluster/deploy -run Ansible -count=1
```

- [ ] **Step 4: Commit**

```powershell
git add internal/cluster/deploy deploy/ansible/cheesewaf-cluster/README.md
git commit -m "feat: generate cluster ansible package"
```

### Task 6: Add Temporary SSH Deployment Runner

**Files:**
- Create: `internal/cluster/deploy/ssh.go`
- Create: `internal/cluster/deploy/ssh_test.go`
- Modify: `internal/api/handler/cluster.go`

- [ ] **Step 1: Write test proving credentials are not persisted**

```go
func TestSSHDeploymentDoesNotPersistCredentialsByDefault(t *testing.T) {
	rec := NewMemoryAuditRecorder()
	runner := NewSSHRunner(SSHRunnerOptions{Audit: rec})
	err := runner.Prepare(context.Background(), SSHDeploymentRequest{
		Host: "192.0.2.10",
		User: "root",
		Password: "secret",
		SaveCredential: false,
	})
	if err != nil { t.Fatal(err) }
	if runner.StoredCredentialCount() != 0 {
		t.Fatal("temporary SSH deployment must not persist credentials")
	}
	if !rec.Contains("ssh_deploy.prepare") {
		t.Fatal("deployment must be audited")
	}
}
```

- [ ] **Step 2: Implement runner interface**

Implement interfaces only in M2:

```go
type SSHRunner interface {
	Check(ctx context.Context, req SSHDeploymentRequest) (CheckResult, error)
	Deploy(ctx context.Context, req SSHDeploymentRequest) (DeployResult, error)
}
```

Use `exec.CommandContext` to call system `ssh` only after validating host, user, port, and command arguments. Do not shell-concatenate user-controlled strings.

- [ ] **Step 3: Add API endpoint**

Add authenticated endpoints:

```text
POST /api/cluster/deploy/check
POST /api/cluster/deploy/run
POST /api/cluster/deploy/ansible
```

RBAC permission: `write:cluster`.

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/deploy ./internal/api/handler -run Cluster -count=1
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/deploy internal/api/handler/cluster.go internal/api/handler/cluster_test.go
git commit -m "feat: add cluster deployment runner api"
```

### Task 7: Add Join Tokens And Node Certificates

**Files:**
- Create: `internal/cluster/identity/pki.go`
- Create: `internal/cluster/identity/pki_test.go`
- Modify: `internal/api/handler/cluster.go`
- Modify: `internal/cli/cluster.go`

- [ ] **Step 1: Write token and cert tests**

```go
func TestJoinTokenIsOneTimeAndExpires(t *testing.T) {
	svc := NewMemoryIdentityService(testClock(time.Unix(1000, 0)))
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil { t.Fatal(err) }
	if err := svc.ConsumeJoinToken(token.Value); err != nil { t.Fatal(err) }
	if err := svc.ConsumeJoinToken(token.Value); err == nil {
		t.Fatal("join token must not be reusable")
	}
}

func TestIssuedNodeCertificateContainsNodeIdentity(t *testing.T) {
	svc := NewMemoryIdentityService(testClock(time.Unix(1000, 0)))
	cert, err := svc.IssueNodeCertificate(NodeIdentity{
		NodeID: "waf-a",
		Role: "waf",
		ClusterID: "cw-test",
		AdvertiseAddr: "10.0.0.1:9444",
	})
	if err != nil { t.Fatal(err) }
	if !strings.Contains(cert.Subject.CommonName, "waf-a") {
		t.Fatalf("node certificate subject missing node id: %s", cert.Subject.CommonName)
	}
}
```

- [ ] **Step 2: Implement identity service**

Implement:

```go
type IdentityService interface {
	CreateJoinToken(role string, ttl time.Duration, maxUses int) (JoinToken, error)
	ConsumeJoinToken(value string) error
	IssueNodeCertificate(identity NodeIdentity) (*x509.Certificate, error)
	RevokeNode(nodeID string, reason string) error
}
```

Tokens must be random, hashed at rest, have expiry, max use count, and audit fields.

- [ ] **Step 3: Expose API and CLI**

Add:

```text
POST /api/cluster/join-tokens
DELETE /api/cluster/join-tokens/{id}
POST /api/cluster/nodes/{id}/revoke
```

CLI:

```text
cheesewaf cluster token create --role waf --ttl 15m --uses 1
cheesewaf cluster token revoke TOKEN_ID
```

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/identity ./internal/api/handler ./internal/cli -run "Join|Token|Certificate|Cluster" -count=1
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/identity internal/api/handler/cluster.go internal/cli/cluster.go
git commit -m "feat: add cluster join tokens and node certificates"
```

---

## M3: Built-In Consistency, Heartbeat, And Protection Mode

### Task 8: Add Multi-Path Heartbeat And Cluster Health

**Files:**
- Create: `internal/cluster/health/health.go`
- Create: `internal/cluster/health/health_test.go`
- Modify: `internal/api/router.go`
- Modify: `internal/api/handler/cluster.go`

- [ ] **Step 1: Write health tests**

```go
func TestNodeEntersProtectionModeAfterHeartbeatLoss(t *testing.T) {
	clock := fakeClock(time.Unix(1000, 0))
	tracker := NewTracker(clock, TrackerConfig{
		HeartbeatTimeout: 3 * time.Second,
		ReconnectAttempts: 5,
	})
	tracker.MarkHeartbeat("waf-a", HeartbeatKindDCS)
	clock.Advance(4 * time.Second)
	status := tracker.Status("waf-a")
	if status.Mode != "reconnecting" {
		t.Fatalf("mode=%s, want reconnecting", status.Mode)
	}
	clock.Advance(50 * time.Second)
	status = tracker.Status("waf-a")
	if status.Mode != "protection" {
		t.Fatalf("mode=%s, want protection", status.Mode)
	}
	if status.CanWriteConfig {
		t.Fatal("protection mode must freeze config writes")
	}
}
```

- [ ] **Step 2: Implement health model**

Support heartbeat kinds:

```go
const (
	HeartbeatKindDCS HeartbeatKind = "cluster-consistency"
	HeartbeatKindPeer HeartbeatKind = "node-interconnect"
	HeartbeatKindTraffic HeartbeatKind = "traffic-health"
	HeartbeatKindSelf HeartbeatKind = "self-check"
)
```

Expose product states:

```go
single-node
ready
reconnecting
protection
isolated
maintenance
```

- [ ] **Step 3: Add health endpoints**

Add:

```text
GET /health/live
GET /health/ready
GET /health/cluster
```

Rules:

- `live` returns process liveness.
- `ready` returns whether node can receive traffic.
- `cluster` returns majority confirmation, coordinator, object version, and protection-mode reason.

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/health ./internal/api/handler -run Health -count=1
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/health internal/api/router.go internal/api/handler/cluster.go
git commit -m "feat: add cluster health and protection mode"
```

### Task 9: Add Built-In Raft And External etcd Adapters

**Files:**
- Create: `internal/cluster/store/store.go`
- Create: `internal/cluster/consensus/raft.go`
- Create: `internal/cluster/consensus/etcd.go`
- Create: `internal/cluster/consensus/consensus_test.go`

- [ ] **Step 1: Write consistency tests**

```go
func TestStoreRejectsWriteWithoutMajority(t *testing.T) {
	store := NewFakeConsensusStore(ConsensusState{MajorityConfirmed: false})
	err := store.Put(context.Background(), objectKey("Node", "waf-a"), []byte(`{}`))
	if err == nil {
		t.Fatal("write must fail without majority confirmation")
	}
	if !errors.Is(err, ErrProtectionMode) {
		t.Fatalf("error=%v, want ErrProtectionMode", err)
	}
}

func TestStoreAllowsReadWithoutMajority(t *testing.T) {
	store := NewFakeConsensusStore(ConsensusState{MajorityConfirmed: false})
	if _, err := store.Get(context.Background(), objectKey("Node", "waf-a")); err != nil {
		t.Fatalf("read must be allowed in protection mode: %v", err)
	}
}
```

- [ ] **Step 2: Implement store interface**

```go
type Store interface {
	Get(ctx context.Context, key Key) ([]byte, error)
	List(ctx context.Context, prefix string) ([][]byte, error)
	Put(ctx context.Context, key Key, value []byte) error
	Delete(ctx context.Context, key Key) error
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
	Status(ctx context.Context) (Status, error)
}
```

- [ ] **Step 3: Implement adapters**

Use built-in Raft as default. External etcd adapter must:

- Require HTTPS or explicit trusted private endpoint.
- Require authentication or mTLS in cluster mode.
- Expose product error messages instead of raw etcd terms in normal UI.

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/store ./internal/cluster/consensus -count=1
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/store internal/cluster/consensus
git commit -m "feat: add cluster consistency store adapters"
```

### Task 10: Add Object Reconciler And Write Freezing

**Files:**
- Create: `internal/cluster/reconcile/reconciler.go`
- Create: `internal/cluster/reconcile/reconciler_test.go`
- Modify: `internal/api/handler/site.go`
- Modify: `internal/api/handler/rule.go`
- Modify: `internal/api/handler/system.go`
- Modify: `internal/api/handler/ip.go`

- [ ] **Step 1: Write protection-mode mutation tests**

```go
func TestConfigMutationBlockedInProtectionMode(t *testing.T) {
	h := newTestHandlerWithClusterState(t, ClusterState{CanWriteConfig: false})
	req := httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(`{"name":"x"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusLocked {
		t.Fatalf("status=%d, want 423", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "保护模式") {
		t.Fatalf("response should explain protection mode: %s", rec.Body.String())
	}
}
```

- [ ] **Step 2: Add mutation guard**

Create middleware:

```go
func RequireClusterWriteAllowed(state ClusterStateProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !state.CanWriteConfig(r.Context()) {
				writeAPIError(w, r, http.StatusLocked, "cluster_protection_mode", "当前节点处于保护模式，暂时不能修改集群配置。")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

Apply to mutating routes only.

- [ ] **Step 3: Add reconciler**

Reconciler converts declarative objects into current config modules:

- `Site` objects -> `config.Sites`
- `WAFRuleSet` objects -> custom rules
- `IPPolicy` objects -> `protection.ip`
- `BotPolicy` objects -> `protection.bot`
- `Certificate` objects -> cert files and site references

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/reconcile ./internal/api/handler -run "Cluster|Protection|Site|Rule" -count=1
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/reconcile internal/api/handler internal/api/router.go
git commit -m "feat: enforce cluster protection mode writes"
```

---

## M4: Production Traffic Scheduling And Rolling Upgrade

### Task 11: Add Built-In Traffic Scheduler

**Files:**
- Create: `internal/cluster/scheduler/scheduler.go`
- Create: `internal/cluster/scheduler/scheduler_test.go`
- Modify: `internal/proxy/loadbalancer.go`

- [ ] **Step 1: Write scheduling tests**

```go
func TestSchedulerOnlySelectsSyncedReadyNodes(t *testing.T) {
	s := NewScheduler(Policy{Algorithm: "least-connections"})
	nodes := []NodeTarget{
		{ID: "a", Ready: true, ConfigSynced: true, ActiveConnections: 10},
		{ID: "b", Ready: true, ConfigSynced: false, ActiveConnections: 1},
		{ID: "c", Ready: false, ConfigSynced: true, ActiveConnections: 0},
	}
	target, err := s.Pick(context.Background(), RequestContext{}, nodes)
	if err != nil { t.Fatal(err) }
	if target.ID != "a" {
		t.Fatalf("selected %s, want a", target.ID)
	}
}
```

- [ ] **Step 2: Implement algorithms**

Support:

- weighted round robin
- least connections
- source IP hash
- cookie affinity
- same-region first
- only-synced-node filter
- pressure-based weight reduction
- circuit breaker

- [ ] **Step 3: Integrate with proxy**

Proxy must preserve:

- real client IP metadata
- WebSocket
- SSE
- HTTP/2
- request and trace IDs

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/scheduler ./internal/proxy -run "Scheduler|LoadBalancer|WebSocket|SSE" -count=1
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/scheduler internal/proxy/loadbalancer.go
git commit -m "feat: add production cluster traffic scheduler"
```

### Task 12: Add Rolling Upgrade And Rollback

**Files:**
- Create: `internal/cluster/upgrade/upgrade.go`
- Create: `internal/cluster/upgrade/upgrade_test.go`
- Modify: `internal/api/handler/cluster.go`
- Modify: `internal/cli/cluster.go`
- Create: `web/src/pages/Cluster/ClusterUpgrade.tsx`

- [ ] **Step 1: Write upgrade plan tests**

```go
func TestUpgradeStopsWhenNodeFailsAndKeepsOthersServing(t *testing.T) {
	planner := NewUpgradePlanner()
	plan := planner.Plan([]NodeStatus{
		{ID: "a", CanReceiveTraffic: true},
		{ID: "b", CanReceiveTraffic: true},
		{ID: "c", CanReceiveTraffic: true},
	})
	result := ExecuteWithFakeRunner(plan, FakeRunner{FailNode: "b"})
	if !result.Stopped {
		t.Fatal("upgrade must stop after failed node")
	}
	if !result.Node("a").Completed {
		t.Fatal("first node should have completed")
	}
	if result.Node("c").Started {
		t.Fatal("third node must not start after second node failed")
	}
}
```

- [ ] **Step 2: Implement upgrade workflow**

Workflow:

1. Upgrade checks.
2. Create backup.
3. Pause one node from receiving new traffic.
4. Install binary.
5. Restart.
6. Check live/ready/cluster status.
7. Sync config.
8. Resume traffic.
9. Continue next node.
10. If failure occurs, rollback failed node and stop.

- [ ] **Step 3: Expose API and CLI**

API:

```text
POST /api/cluster/upgrade/check
POST /api/cluster/upgrade/start
POST /api/cluster/upgrade/rollback
GET /api/cluster/upgrade/tasks/{id}
```

CLI:

```text
cheesewaf cluster upgrade check --channel canary
cheesewaf cluster upgrade start --channel stable
cheesewaf cluster rollback VERSION
```

Use product labels in UI: 开发版 / 预览版 / 正式版.

- [ ] **Step 4: Run tests**

```powershell
go test ./internal/cluster/upgrade ./internal/api/handler ./internal/cli -run "Upgrade|Rollback|Cluster" -count=1
npm.cmd --prefix web run typecheck -- --pretty false
npm.cmd --prefix web run build
```

- [ ] **Step 5: Commit**

```powershell
git add internal/cluster/upgrade internal/api/handler/cluster.go internal/cli/cluster.go web/src/pages/Cluster/ClusterUpgrade.tsx
git commit -m "feat: add cluster rolling upgrade workflow"
```

---

## End-To-End Verification Gates

Run these before claiming any milestone complete:

```powershell
go test ./cmd/... ./internal/... -count=1
npm.cmd --prefix web run typecheck -- --pretty false
npm.cmd --prefix web run build
git diff --check
```

For M2 and later, add local integration checks:

```powershell
go test ./internal/cluster/... ./internal/api/handler ./internal/cli -count=1
```

For Web UI changes, run existing UI regression tooling:

```powershell
node tmp/full-ui-regression.cjs
```

For deployment work, verify at least:

- Generated Ansible package contains no raw SSH password or private key.
- Temporary SSH mode clears credentials after task completion.
- Cluster API returns `423 Locked` for mutating operations in protection mode.
- `/health/live`, `/health/ready`, and `/health/cluster` return distinct and correct meanings.
- Two-node mode never displays as full HA.
- Two WAF nodes plus one monitor node displays as minimum HA.
- Three WAF nodes display as multi-node HA only after majority confirmation works.

## Documentation Updates

After implementation starts, keep these files in sync:

- `implementation_plan.md`: engineering roadmap and milestone status.
- `task.md`: task checklist and validation notes.
- `progress.md`: public-facing roadmap summary with no secrets.
- `docs/cluster-ha.md`: public cluster design guide.
- `README.md` / `README_CN.md`: only add user-facing status when a milestone is actually implemented.

## Current Non-Implementation Status

This document is a plan only. The current product still runs as a single-node WAF. The repository does not yet contain real cluster heartbeat, majority confirmation, monitor-node runtime, Raft/etcd coordination, cluster object reconciliation, or production cluster traffic scheduling.
