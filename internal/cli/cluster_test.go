package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestClusterStatusShowsStandaloneByDefault(t *testing.T) {
	path := testClusterConfigPath(t)
	oldConfigPath := configPath
	t.Cleanup(func() { configPath = oldConfigPath })

	cmd := newRootCommand()
	buf := bytes.NewBuffer(nil)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--config", path, "cluster", "status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cluster status failed: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "单机模式") {
		t.Fatalf("cluster status did not show standalone mode: %s", out)
	}
	if !strings.Contains(out, "集群状态: 未启用") {
		t.Fatalf("cluster status did not show disabled cluster: %s", out)
	}
}

func TestClusterInitWritesSingleNodeClusterConfig(t *testing.T) {
	path := testClusterConfigPath(t)
	oldConfigPath := configPath
	t.Cleanup(func() { configPath = oldConfigPath })

	cmd := newRootCommand()
	buf := bytes.NewBuffer(nil)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", path,
		"cluster", "init",
		"--cluster-id", "cw-test",
		"--node-id", "waf-a",
		"--advertise-addr", "127.0.0.1:9444",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cluster init failed: %v\n%s", err, buf.String())
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Deployment.Mode != "cluster" || !cfg.Cluster.Enabled {
		t.Fatalf("cluster init did not enable cluster mode: %+v", cfg.Cluster)
	}
	if cfg.Cluster.HAMode != "single-node" {
		t.Fatalf("ha_mode=%q, want single-node", cfg.Cluster.HAMode)
	}
	if cfg.Cluster.ClusterID != "cw-test" || cfg.Cluster.NodeID != "waf-a" {
		t.Fatalf("unexpected cluster identity: %+v", cfg.Cluster)
	}
	if len(cfg.Cluster.Nodes) != 1 || cfg.Cluster.Nodes[0].Role != "waf" {
		t.Fatalf("expected one WAF node, got %+v", cfg.Cluster.Nodes)
	}
}

func TestClusterExportOutputsDeclarativeObjects(t *testing.T) {
	path := testClusterConfigPath(t)
	oldConfigPath := configPath
	t.Cleanup(func() { configPath = oldConfigPath })

	initCmd := newRootCommand()
	initCmd.SetOut(bytes.NewBuffer(nil))
	initCmd.SetErr(bytes.NewBuffer(nil))
	initCmd.SetArgs([]string{
		"--config", path,
		"cluster", "init",
		"--cluster-id", "cw-test",
		"--node-id", "waf-a",
		"--advertise-addr", "127.0.0.1:9444",
	})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("cluster init failed: %v", err)
	}

	exportCmd := newRootCommand()
	buf := bytes.NewBuffer(nil)
	exportCmd.SetOut(buf)
	exportCmd.SetErr(buf)
	exportCmd.SetArgs([]string{"--config", path, "cluster", "export"})
	if err := exportCmd.Execute(); err != nil {
		t.Fatalf("cluster export failed: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"kind: ClusterPolicy", "kind: Node", "cw-test", "waf-a", "single-node"} {
		if !strings.Contains(out, want) {
			t.Fatalf("cluster export missing %q:\n%s", want, out)
		}
	}
}

func testClusterConfigPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	raw := []byte(`
server:
  listen: "127.0.0.1:8080"
  admin_listen: "127.0.0.1:9443"
storage:
  sqlite:
    path: "./data/cheesewaf.db"
sites:
  - id: "default"
    name: "localhost"
    domains: ["localhost"]
    upstreams:
      - address: "127.0.0.1:9000"
        weight: 1
    enabled: true
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
