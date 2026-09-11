package nativeraft

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
)

func TestLoadTLSConfigRequiresNodeIDBoundCertificate(t *testing.T) {
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:9444"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	for path, data := range map[string][]byte{caPath: bundle.CAPEM, certPath: bundle.CertPEM, keyPath: bundle.KeyPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadTLSConfig(&TLSOptions{CAFile: caPath, CertFile: certPath, KeyFile: keyPath}, "node-a"); err != nil {
		t.Fatalf("node-bound certificate rejected: %v", err)
	}
	if _, err := loadTLSConfig(&TLSOptions{CAFile: caPath, CertFile: certPath, KeyFile: keyPath}, "node-b"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "node id") {
		t.Fatalf("mismatched node certificate error=%v, want node id binding rejection", err)
	}
}

func TestVerifyPeerCertificateChecksCAAndNodeID(t *testing.T) {
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a", Clock: identity.NewFakeClock(time.Now().UTC())})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:9444"})
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(bundle.CertPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.CAPEM) {
		t.Fatal("failed to parse CA")
	}
	if err := verifyPeerCertificate([][]byte{cert.Raw}, roots, "node-a"); err != nil {
		t.Fatalf("valid peer certificate rejected: %v", err)
	}
	if err := verifyPeerCertificate([][]byte{cert.Raw}, roots, "node-b"); err == nil {
		t.Fatal("peer certificate for node-a accepted as node-b")
	}
}

func TestTLSRaftTransportReplicatesOnlyWithMutualNodeCertificates(t *testing.T) {
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	writeBundle := func(nodeID string) (TLSOptions, string) {
		bundle, issueErr := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: nodeID, Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:0"})
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		dir := t.TempDir()
		if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil {
			t.Fatal(chmodErr)
		}
		paths := TLSOptions{CAFile: filepath.Join(dir, "ca.pem"), CertFile: filepath.Join(dir, "node.crt"), KeyFile: filepath.Join(dir, "node.key")}
		for path, data := range map[string][]byte{paths.CAFile: bundle.CAPEM, paths.CertFile: bundle.CertPEM, paths.KeyFile: bundle.KeyPEM} {
			if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		return paths, dir
	}
	leaderTLS, leaderDir := writeBundle("node-a")
	followerTLS, followerDir := writeBundle("node-b")
	leader, err := New(Options{Profile: "production", ClusterID: "cluster-a", NodeID: "node-a", DataDir: leaderDir, BindAddress: "127.0.0.1:0", Mode: ModeBootstrap, TLS: &leaderTLS})
	if err != nil {
		t.Fatalf("New leader: %v", err)
	}
	defer leader.Close()
	if err := leader.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	follower, err := New(Options{Profile: "production", ClusterID: "cluster-a", NodeID: "node-b", DataDir: followerDir, BindAddress: "127.0.0.1:0", Mode: ModeJoin, TLS: &followerTLS})
	if err != nil {
		t.Fatalf("New follower: %v", err)
	}
	defer follower.Close()
	if err := follower.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForLeader(t, leader)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := leader.Join(ctx, Member{ID: follower.NodeID(), Address: follower.Address()}); err != nil {
		t.Fatalf("TLS Join: %v", err)
	}
	if err := follower.Health(ctx); err != nil {
		t.Fatalf("TLS follower Health: %v", err)
	}
}
