package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectServiceStatusUsesConfiguredRuntimeDir(t *testing.T) {
	originalConfigPath := configPath
	originalDataDir := dataDir
	t.Cleanup(func() {
		configPath = originalConfigPath
		dataDir = originalDataDir
	})

	root := t.TempDir()
	runtimeDir := filepath.Join(root, "custom-run")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	configPath = filepath.Join(root, "cheesewaf.yaml")
	dataDir = filepath.Join(root, "fallback-data")
	config := fmt.Sprintf(`server:
  listen: ":18080"
  admin_listen: "127.0.0.1:19443"
setup:
  data_dir: %q
  runtime_dir: %q
storage:
  sqlite:
    path: %q
sites:
  - id: "default"
    name: "default"
    domains: ["localhost"]
    upstreams:
      - address: "127.0.0.1:9000"
        weight: 1
    enabled: true
`, filepath.ToSlash(filepath.Join(root, "data")), filepath.ToSlash(runtimeDir), filepath.ToSlash(filepath.Join(root, "data", "cheesewaf.db")))
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(pidPath(runtimeDir), []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}

	snapshot, err := inspectServiceStatus()
	if err != nil {
		t.Fatalf("inspectServiceStatus() error = %v", err)
	}
	if snapshot.RuntimeDir != runtimeDir {
		t.Fatalf("runtime dir = %q, want %q", snapshot.RuntimeDir, runtimeDir)
	}
	if snapshot.PID != os.Getpid() || !snapshot.Running || snapshot.Stale {
		t.Fatalf("unexpected current-process snapshot: %+v", snapshot)
	}
}

func TestInspectServiceStatusDetectsMissingAndStalePID(t *testing.T) {
	originalConfigPath := configPath
	originalDataDir := dataDir
	t.Cleanup(func() {
		configPath = originalConfigPath
		dataDir = originalDataDir
	})

	root := t.TempDir()
	configPath = filepath.Join(root, "missing.yaml")
	dataDir = filepath.Join(root, "data")
	runtimeDir := filepath.Join(dataDir, "run")

	missing, err := inspectServiceStatus()
	if err != nil {
		t.Fatalf("inspect missing status: %v", err)
	}
	if missing.HasPIDFile || missing.Running || missing.RuntimeDir != runtimeDir {
		t.Fatalf("unexpected missing snapshot: %+v", missing)
	}

	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	const stalePID = 4194303
	if err := os.WriteFile(pidPath(runtimeDir), []byte(fmt.Sprint(stalePID)), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}
	stale, err := inspectServiceStatus()
	if err != nil {
		t.Fatalf("inspect stale status: %v", err)
	}
	if !stale.HasPIDFile || stale.PID != stalePID || stale.Running || !stale.Stale {
		t.Fatalf("unexpected stale snapshot: %+v", stale)
	}
}

func TestStopCommandRemovesStalePIDFile(t *testing.T) {
	originalConfigPath := configPath
	originalDataDir := dataDir
	t.Cleanup(func() {
		configPath = originalConfigPath
		dataDir = originalDataDir
		stopCmd.SetOut(nil)
		stopCmd.SetErr(nil)
	})

	root := t.TempDir()
	configPath = filepath.Join(root, "missing.yaml")
	dataDir = filepath.Join(root, "data")
	runtimeDir := filepath.Join(dataDir, "run")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	pidFile := pidPath(runtimeDir)
	if err := os.WriteFile(pidFile, []byte("4194303"), 0o644); err != nil {
		t.Fatalf("write pid: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	stopCmd.SetOut(&out)
	stopCmd.SetErr(&errOut)
	stopCmd.Run(stopCmd, nil)

	if errOut.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", errOut.String())
	}
	if !strings.Contains(out.String(), "removed stale pid file") {
		t.Fatalf("expected stale pid cleanup message, got %q", out.String())
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("expected pid file to be removed, stat err=%v", err)
	}
}
