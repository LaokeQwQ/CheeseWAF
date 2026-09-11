package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
)

func TestRunRejectsInvalidOptionsBeforeOpeningBackends(t *testing.T) {
	err := run(context.Background(), []string{"--cluster-id", " cluster-a", "--data-dir", t.TempDir(), "--postgres-dsn", "postgres://secret:password@127.0.0.1/control?sslmode=disable"}, nilWriter{}, nilWriter{})
	if err == nil || !strings.Contains(err.Error(), "cluster") {
		t.Fatalf("run error=%v, want cluster validation", err)
	}
	if strings.Contains(err.Error(), "password") {
		t.Fatalf("DSN leaked: %v", err)
	}
}

func TestRunDoesNotEchoUnexpectedDSNArguments(t *testing.T) {
	err := run(context.Background(), []string{"--", "postgres://secret:password@db.example/control"}, nilWriter{}, nilWriter{})
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Fatalf("run error=%v, want unexpected argument rejection", err)
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "db.example") {
		t.Fatalf("unexpected argument leaked DSN: %v", err)
	}
}

func TestRunUsesExplicitShortStartupTimeout(t *testing.T) {
	started := time.Now()
	caFile, certFile, keyFile := testTLSFiles(t)
	err := run(context.Background(), []string{"--cluster-id", "cluster-a", "--data-dir", t.TempDir(), "--ca-file", caFile, "--cert-file", certFile, "--key-file", keyFile, "--postgres-dsn", "postgres://127.0.0.1:1/control?sslmode=disable", "--timeout", "1ms"}, nilWriter{}, nilWriter{})
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("run error=%v duration=%s", err, time.Since(started))
	}
}

func testTLSFiles(t *testing.T) (string, string, string) {
	t.Helper()
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: "node-a", Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:9451"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile, certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	if err := os.WriteFile(caFile, bundle.CAPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, bundle.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, bundle.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, certFile, keyFile
}

func TestRunHelpIsSuccessful(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out, &out); err != nil {
		t.Fatalf("help error=%v", err)
	}
	help := out.String()
	for _, flag := range []string{"-ca-file", "-cert-file", "-key-file"} {
		if !strings.Contains(help, flag) {
			t.Fatalf("help output missing %s: %s", flag, help)
		}
	}
	if strings.Contains(help, "InsecureTestMode") || strings.Contains(help, "insecure-test") {
		t.Fatalf("CLI exposed test-only insecure mode: %s", help)
	}
}

type nilWriter struct{}

func (nilWriter) Write(p []byte) (int, error) { return len(p), nil }
