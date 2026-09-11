package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	tls := testTLSOptions(t, "node-a")
	return Options{Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a", NodeID: "node-a", DataDir: t.TempDir(), Listen: "127.0.0.1:0", RaftListen: "127.0.0.1:0", Mode: nativeraft.ModeBootstrap, PostgreSQLDSN: "postgres://control:secret@127.0.0.1:5432/control?sslmode=disable", CAFile: tls.CAFile, CertFile: tls.CertFile, KeyFile: tls.KeyFile, Timeout: time.Second}
}

func testTLSOptions(t *testing.T, nodeID string) nativeraft.TLSOptions {
	t.Helper()
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: nodeID, Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:9451"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	paths := nativeraft.TLSOptions{CAFile: filepath.Join(dir, "ca.pem"), CertFile: filepath.Join(dir, "node.crt"), KeyFile: filepath.Join(dir, "node.key")}
	for path, data := range map[string][]byte{paths.CAFile: bundle.CAPEM, paths.CertFile: bundle.CertPEM, paths.KeyFile: bundle.KeyPEM} {
		perm := os.FileMode(0o644)
		if path == paths.KeyFile {
			perm = 0o600
		}
		if err := os.WriteFile(path, data, perm); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func writeMismatchedCertificate(t *testing.T, caPath, certPath, keyPath, nodeID string) {
	t.Helper()
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:9451"}); err != nil {
		t.Fatal(err)
	}
	other, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: nodeID, Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:9451"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, other.CAPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, other.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, other.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOptionsRejectsMissingProductionDependenciesBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Options)
		want string
	}{
		{"temporary", func(o *Options) { o.Profile = "temporary" }, "production"},
		{"profile whitespace", func(o *Options) { o.Profile = " production" }, "production"},
		{"missing postgres", func(o *Options) { o.PostgreSQLDSN = "" }, "PostgreSQL"},
		{"missing native-raft TLS", func(o *Options) { o.CAFile, o.CertFile, o.KeyFile = "", "", "" }, "TLS"},
		{"implicit raft mode", func(o *Options) { o.Mode = "" }, "bootstrap or join"},
		{"cluster whitespace", func(o *Options) { o.ClusterID = " cluster-a" }, "cluster"},
		{"node invisible whitespace", func(o *Options) { o.NodeID = "node\u200b-a" }, "node"},
		{"public HTTP", func(o *Options) { o.Listen = "0.0.0.0:9445" }, "loopback"},
		{"public raft", func(o *Options) { o.RaftListen = "0.0.0.0:9444" }, "loopback"},
		{"remote insecure PostgreSQL", func(o *Options) {
			o.PostgreSQLDSN = "postgres://control:secret@db.example:5432/control?sslmode=disable"
		}, "TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			tc.edit(&opts)
			err := ValidateOptions(opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateOptions error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("validation exposed PostgreSQL credential: %v", err)
			}
		})
	}
}

func TestValidateOptionsRejectsBadNativeRaftTLSMaterial(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Options)
		want string
	}{
		{"bad key permissions", func(o *Options) { _ = os.Chmod(o.KeyFile, 0o644) }, "permissions"},
		{"bad certificate permissions", func(o *Options) { _ = os.Chmod(o.CertFile, 0o640) }, "permissions"},
		{"missing certificate", func(o *Options) { _ = os.Remove(o.CertFile) }, "certificate"},
		{"certificate SAN mismatch", func(o *Options) { writeMismatchedCertificate(t, o.CAFile, o.CertFile, o.KeyFile, "other-node") }, "SAN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			tc.edit(&opts)
			err := ValidateOptions(opts)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("ValidateOptions error=%v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("TLS material leaked: %v", err)
			}
		})
	}
}

func TestNativeRaftOptionsCarryValidatedTLSMaterial(t *testing.T) {
	opts := testOptions(t)
	if err := ValidateOptions(opts); err != nil {
		t.Fatalf("valid TLS options rejected: %v", err)
	}
	raftOpts := nativeRaftOptions(opts)
	if raftOpts.TLS == nil {
		t.Fatal("native-raft TLS options are nil")
	}
	if raftOpts.TLS.CAFile != opts.CAFile || raftOpts.TLS.CertFile != opts.CertFile || raftOpts.TLS.KeyFile != opts.KeyFile {
		t.Fatalf("native-raft TLS options=%+v, want paths from runtime options", raftOpts.TLS)
	}
}
