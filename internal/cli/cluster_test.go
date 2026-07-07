package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
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

func TestClusterTokenCreatePersistsHashOnlyAndRevoke(t *testing.T) {
	path := testClusterConfigPath(t)
	root := t.TempDir()
	oldConfigPath := configPath
	oldDataDir := dataDir
	t.Cleanup(func() {
		configPath = oldConfigPath
		dataDir = oldDataDir
	})

	createCmd := newRootCommand()
	buf := bytes.NewBuffer(nil)
	createCmd.SetOut(buf)
	createCmd.SetErr(buf)
	createCmd.SetArgs([]string{
		"--config", path,
		"--data-dir", root,
		"cluster", "token", "create",
		"--role", "waf",
		"--ttl", "15m",
		"--uses", "1",
	})
	if err := createCmd.Execute(); err != nil {
		t.Fatalf("cluster token create failed: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "加入令牌") || !strings.Contains(out, "令牌ID") {
		t.Fatalf("unexpected create output: %s", out)
	}
	tokenID := extractCLIValue(out, "令牌ID:")
	tokenValue := extractCLIValue(out, "加入令牌:")
	if tokenID == "" || tokenValue == "" {
		t.Fatalf("missing token id/value in output: %s", out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "cluster", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(tokenValue)) {
		t.Fatal("cluster token state must not persist raw token")
	}

	revokeCmd := newRootCommand()
	buf = bytes.NewBuffer(nil)
	revokeCmd.SetOut(buf)
	revokeCmd.SetErr(buf)
	revokeCmd.SetArgs([]string{
		"--config", path,
		"--data-dir", root,
		"cluster", "token", "revoke",
		tokenID,
	})
	if err := revokeCmd.Execute(); err != nil {
		t.Fatalf("cluster token revoke failed: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "已撤销") {
		t.Fatalf("unexpected revoke output: %s", buf.String())
	}
}

func TestClusterJoinWritesCertificatesAndConfig(t *testing.T) {
	path := testClusterConfigPath(t)
	root := t.TempDir()
	oldConfigPath := configPath
	oldDataDir := dataDir
	t.Cleanup(func() {
		configPath = oldConfigPath
		dataDir = oldDataDir
	})
	configPath = path
	dataDir = root
	svc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	var signedBundle identity.NodeCertificateBundle
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cluster/join" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["token"] != "join-secret" || payload["node_id"] != "waf-b" {
			t.Fatalf("unexpected join payload: %+v", payload)
		}
		if strings.TrimSpace(payload["csr"]) == "" {
			t.Fatalf("join payload must include csr: %+v", payload)
		}
		token, err := svc.CreateJoinToken("waf", time.Minute, 1)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := svc.EnrollNodeWithCSR(token.Value, identity.NodeIdentity{
			NodeID:        "waf-b",
			Role:          "waf",
			ClusterID:     "cw-test",
			AdvertiseAddr: "127.0.0.1:9444",
		}, []byte(payload["csr"]))
		if err != nil {
			t.Fatal(err)
		}
		signedBundle = bundle.Bundle
		writeTestEnvelope(t, w, map[string]any{
			"cluster_id":     "cw-test",
			"node_id":        "waf-b",
			"role":           "waf",
			"advertise_addr": "127.0.0.1:9444",
			"listen":         "127.0.0.1:9444",
			"interconnect": map[string]any{
				"listen":         "127.0.0.1:9444",
				"advertise_addr": "127.0.0.1:9444",
				"mtls_required":  true,
			},
			"certificates": map[string]string{
				"ca":   string(signedBundle.CAPEM),
				"cert": string(signedBundle.CertPEM),
			},
			"node": map[string]any{
				"node_id":            "waf-b",
				"role":               "waf",
				"cluster_id":         "cw-test",
				"advertise_addr":     "127.0.0.1:9444",
				"joined_at":          time.Unix(1000, 0).UTC(),
				"certificate_serial": signedBundle.Certificate.SerialNumber.String(),
				"certificate_expiry": signedBundle.Certificate.NotAfter,
			},
		})
	}))
	defer server.Close()

	cmd := newRootCommand()
	buf := bytes.NewBuffer(nil)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--config", path,
		"--data-dir", root,
		"cluster", "join",
		"--controller", server.URL,
		"--allow-insecure-http",
		"--token", "join-secret",
		"--node-id", "waf-b",
		"--role", "waf",
		"--advertise-addr", "127.0.0.1:9444",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cluster join failed: %v\n%s", err, buf.String())
	}
	if strings.Contains(buf.String(), "join-secret") {
		t.Fatal("cluster join output must not leak token")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Deployment.Mode != "cluster" || !cfg.Cluster.Enabled || cfg.Cluster.ClusterID != "cw-test" || cfg.Cluster.NodeID != "waf-b" {
		t.Fatalf("cluster join did not write local identity: %+v", cfg.Cluster)
	}
	if cfg.Cluster.Interconnect.CAFile == "" || cfg.Cluster.Interconnect.CertFile == "" || cfg.Cluster.Interconnect.KeyFile == "" {
		t.Fatalf("cluster join did not write mTLS material paths: %+v", cfg.Cluster.Interconnect)
	}
	info, err := os.Stat(cfg.Cluster.Interconnect.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if enforcePrivateFileModeInCLITest() && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("node private key permissions=%#o, want private", info.Mode().Perm())
	}
	key, err := readTestECPrivateKey(cfg.Cluster.Interconnect.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := readTestCertificate(cfg.Cluster.Interconnect.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type=%T, want ECDSA", cert.PublicKey)
	}
	if certKey.X.Cmp(key.PublicKey.X) != 0 || certKey.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("node certificate must be signed for the locally generated private key")
	}
}

func TestClusterJoinForceRestoresExistingFilesWhenConfigFails(t *testing.T) {
	root := t.TempDir()
	oldDataDir := dataDir
	t.Cleanup(func() { dataDir = oldDataDir })
	dataDir = root
	dir := filepath.Join(root, "cluster", "certs", "waf-b")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	paths := clusterJoinPaths{
		CAFile:   filepath.Join(dir, "ca.pem"),
		CertFile: filepath.Join(dir, "node.crt"),
		KeyFile:  filepath.Join(dir, "node.key"),
	}
	originalCA := []byte("old-ca")
	originalCert := []byte("old-cert")
	originalKey := []byte("old-key")
	if err := os.WriteFile(paths.CAFile, originalCA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.CertFile, originalCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.KeyFile, originalKey, 0o600); err != nil {
		t.Fatal(err)
	}
	written, err := writeClusterJoinFiles(clusterJoinAPIResponse{
		NodeID: "waf-b",
		Certificates: struct {
			CA   string `json:"ca"`
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}{CA: "new-ca", Cert: "new-cert"},
	}, clusterJoinOptions{Force: true}, clusterJoinLocalIdentity{KeyPEM: []byte("new-key")})
	if err != nil {
		t.Fatal(err)
	}
	cleanupClusterJoinFiles(written)
	assertFileBytes(t, paths.CAFile, originalCA)
	assertFileBytes(t, paths.CertFile, originalCert)
	assertFileBytes(t, paths.KeyFile, originalKey)
}

func TestClusterJoinConfigFailureMentionsControllerCompensation(t *testing.T) {
	result := clusterJoinAPIResponse{
		ClusterID:     "cw-test",
		NodeID:        "waf-b",
		Role:          "waf",
		AdvertiseAddr: "10.0.0.2:9444",
	}
	paths := clusterJoinPaths{
		CAFile:   filepath.Join(t.TempDir(), "ca.pem"),
		CertFile: filepath.Join(t.TempDir(), "node.crt"),
		KeyFile:  filepath.Join(t.TempDir(), "node.key"),
	}
	err := clusterJoinConfigApplyError(result, paths, fmt.Errorf("disk full"))
	if err == nil {
		t.Fatal("expected error")
	}
	message := err.Error()
	for _, want := range []string{"controller accepted the join", "consumed the token", "Revoke or rotate node", "waf-b"} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected message to contain %q, got %q", want, message)
		}
	}
}

func enforcePrivateFileModeInCLITest() bool {
	return os.PathSeparator == '/'
}

func TestClusterJoinRejectsPlainHTTPByDefault(t *testing.T) {
	_, err := validateClusterJoinControllerURL("http://127.0.0.1:9443", false)
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("expected HTTPS rejection, got %v", err)
	}
	if _, err := validateClusterJoinControllerURL("http://127.0.0.1:9443", true); err != nil {
		t.Fatalf("allow-insecure-http should permit explicit lab HTTP: %v", err)
	}
}

func writeTestEnvelope(t *testing.T, w http.ResponseWriter, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(dto.Response{Data: data}); err != nil {
		t.Fatal(err)
	}
}

func readTestECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, os.ErrInvalid
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func readTestCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, os.ErrInvalid
	}
	return x509.ParseCertificate(block.Bytes)
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s=%q, want %q", path, got, want)
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

func extractCLIValue(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
