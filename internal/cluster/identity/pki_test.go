package identity

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJoinTokenIsOneTimeAndExpires(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	svc, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if token.Value == "" || token.Hash == "" {
		t.Fatalf("token value and hash must be set: %+v", token)
	}
	if strings.Contains(token.Hash, token.Value) {
		t.Fatal("token hash must not contain raw token value")
	}
	if err := svc.ConsumeJoinToken(token.Value); err != nil {
		t.Fatal(err)
	}
	if err := svc.ConsumeJoinToken(token.Value); err == nil {
		t.Fatal("join token must not be reusable")
	}

	expired, err := svc.CreateJoinToken("monitor", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if err := svc.ConsumeJoinToken(expired.Value); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestIssuedNodeCertificateContainsNodeIdentity(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	svc, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := svc.IssueNodeCertificate(NodeIdentity{
		NodeID:        "waf-a",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.1:9444",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cert.Subject.CommonName, "waf-a") {
		t.Fatalf("node certificate subject missing node id: %s", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "waf-a" {
		t.Fatalf("node certificate DNSNames=%v, want waf-a", cert.DNSNames)
	}
	if err := svc.RevokeNode("waf-a", "rotated"); err != nil {
		t.Fatal(err)
	}
	if !svc.IsRevoked("waf-a") {
		t.Fatal("node should be revoked")
	}
}

func TestIssuedNodeCertificateBundleIsSignedAndParseable(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	svc, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := svc.IssueNodeCertificateBundle(NodeIdentity{
		NodeID:        "waf-a",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.1:9444",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.CertPEM) == 0 || len(bundle.KeyPEM) == 0 || len(bundle.CAPEM) == 0 {
		t.Fatalf("certificate bundle must contain cert, key and CA PEM")
	}
	certBlock, _ := pem.Decode(bundle.CertPEM)
	caBlock, _ := pem.Decode(bundle.CAPEM)
	keyBlock, _ := pem.Decode(bundle.KeyPEM)
	if certBlock == nil || caBlock == nil || keyBlock == nil {
		t.Fatal("certificate bundle PEM blocks must be parseable")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     "waf-a",
		CurrentTime: clock.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("node certificate should verify against cluster CA: %v", err)
	}
}

func TestClusterCAPersistsWithIdentityState(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	statePath := filepath.Join(t.TempDir(), "identity.json")
	first, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	firstBundle, err := first.IssueNodeCertificateBundle(NodeIdentity{
		NodeID:        "waf-a",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.1:9444",
	})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	nextBundle, err := reloaded.IssueNodeCertificateBundle(NodeIdentity{
		NodeID:        "waf-b",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.2:9444",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBundle.CAPEM) != string(nextBundle.CAPEM) {
		t.Fatal("cluster CA must persist across identity service reloads")
	}
}

func TestJoinTokenStatePersistsWithoutRawToken(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	statePath := filepath.Join(t.TempDir(), "identity.json")
	svc, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token.Value) {
		t.Fatal("state file must not contain raw join token")
	}
	reloaded, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	tokens := reloaded.ListJoinTokens()
	if len(tokens) != 1 {
		t.Fatalf("persisted token count=%d, want 1", len(tokens))
	}
	if tokens[0].Value != "" || tokens[0].Hash == "" {
		t.Fatalf("listed tokens must be redacted and hashed: %+v", tokens[0])
	}
	if err := reloaded.ConsumeJoinToken(token.Value); err != nil {
		t.Fatalf("reloaded service should accept persisted token: %v", err)
	}
}

func TestValidateJoinTokenDoesNotConsume(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	svc, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateJoinToken(token.Value, "waf"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateJoinToken(token.Value, "waf"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ConsumeJoinToken(token.Value); err != nil {
		t.Fatalf("validated token should still be usable: %v", err)
	}
	if err := svc.ValidateJoinToken(token.Value, "waf"); err == nil {
		t.Fatal("used token should no longer validate")
	}
}

func TestEnrollNodeConsumesRoleScopedTokenAndPersistsNode(t *testing.T) {
	clock := NewFakeClock(time.Unix(1000, 0))
	statePath := filepath.Join(t.TempDir(), "identity.json")
	svc, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	monitorToken, err := svc.CreateJoinToken("monitor", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollNode(monitorToken.Value, NodeIdentity{
		NodeID:        "waf-a",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.1:9444",
	}); err == nil {
		t.Fatal("role-scoped token must not enroll a different node role")
	}
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := svc.EnrollNode(token.Value, NodeIdentity{
		NodeID:        "waf-a",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.1:9444",
	})
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Token.Value != "" || enrollment.Token.Hash != "" {
		t.Fatalf("enrollment response must redact token: %+v", enrollment.Token)
	}
	if enrollment.Node.NodeID != "waf-a" || enrollment.Node.CertificateSerial == "" {
		t.Fatalf("unexpected node registration: %+v", enrollment.Node)
	}
	if len(enrollment.Bundle.CertPEM) == 0 || len(enrollment.Bundle.KeyPEM) == 0 || len(enrollment.Bundle.CAPEM) == 0 {
		t.Fatal("enrollment must return cert/key/ca material")
	}
	if _, err := svc.EnrollNode(token.Value, NodeIdentity{
		NodeID:        "waf-b",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.2:9444",
	}); err == nil {
		t.Fatal("enrollment token must be one-time by default")
	}
	reloaded, err := NewMemoryIdentityService(ServiceOptions{Clock: clock, ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	nodes := reloaded.ListNodes()
	if len(nodes) != 1 || nodes[0].NodeID != "waf-a" {
		t.Fatalf("persisted nodes=%+v, want waf-a", nodes)
	}
	if err := reloaded.RevokeNode("waf-a", "rotated"); err != nil {
		t.Fatal(err)
	}
	nodes = reloaded.ListNodes()
	if len(nodes) != 1 || !nodes[0].Revoked || nodes[0].RevokedReason != "rotated" {
		t.Fatalf("revoked node not reflected in list: %+v", nodes)
	}
}

func TestIdentityStateRejectsWeakPermissions(t *testing.T) {
	if !enforcePOSIXPrivateMode() {
		t.Skip("POSIX mode bits are not reliable on this platform")
	}
	statePath := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(statePath, []byte(`{"tokens":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMemoryIdentityService(ServiceOptions{ClusterID: "cw-test", StatePath: statePath}); err == nil {
		t.Fatal("identity state with group/world permissions must be rejected")
	}
}

func TestIdentityStateWriteUsesPrivatePermissions(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "identity.json")
	svc, err := NewMemoryIdentityService(ServiceOptions{ClusterID: "cw-test", StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateJoinToken("waf", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if enforcePOSIXPrivateMode() && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity state permissions=%#o, want private", info.Mode().Perm())
	}
}
