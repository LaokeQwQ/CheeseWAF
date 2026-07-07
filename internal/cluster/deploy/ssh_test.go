package deploy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHDeploymentDoesNotPersistCredentialsByDefault(t *testing.T) {
	rec := NewMemoryAuditRecorder()
	runner := NewSSHRunner(SSHRunnerOptions{Audit: rec})
	if err := runner.Prepare(context.Background(), SSHDeploymentRequest{
		Host:           "192.0.2.10",
		User:           "root",
		Port:           22,
		SaveCredential: false,
	}); err != nil {
		t.Fatal(err)
	}
	if runner.StoredCredentialCount() != 0 {
		t.Fatal("temporary SSH deployment must not persist credentials")
	}
	if !rec.Contains("ssh_deploy.prepare") {
		t.Fatal("deployment must be audited")
	}
}

func TestSSHRunnerBuildsSafeArgumentVector(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	args, err := runner.BuildSSHArgs(SSHDeploymentRequest{
		Host:   "192.0.2.10",
		User:   "root",
		Port:   2222,
		Action: "check",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "sh -c") || strings.Contains(joined, ";") {
		t.Fatalf("ssh args must not use shell concatenation: %q", joined)
	}
	if got := args[len(args)-2]; got != "root@192.0.2.10" {
		t.Fatalf("target arg=%q", got)
	}
}

func TestSSHRunnerSupportsEphemeralPrivateKeyContent(t *testing.T) {
	rec := NewMemoryAuditRecorder()
	runner := NewSSHRunner(SSHRunnerOptions{Audit: rec})
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nunit-test-key\n-----END OPENSSH PRIVATE KEY-----"
	prepared, cleanup, err := runner.prepareRequest(context.Background(), SSHDeploymentRequest{
		Host:       "192.0.2.10",
		User:       "root",
		Port:       2222,
		PrivateKey: key,
		Action:     "check",
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PrivateKey != "" {
		t.Fatal("prepared request must not keep raw private key content")
	}
	if prepared.identityFile == "" {
		t.Fatal("prepared request should point ssh at a temporary identity file")
	}
	raw, err := os.ReadFile(prepared.identityFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != key {
		t.Fatal("temporary identity file did not contain provided key")
	}
	args, err := runner.BuildSSHArgs(prepared)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "unit-test-key") || rec.Contains("unit-test-key") {
		t.Fatal("private key content must not appear in argv or audit records")
	}
	redacted := redactedSSHArgs(args)
	if strings.Contains(strings.Join(redacted, " "), prepared.identityFile) {
		t.Fatal("redacted ssh args must not expose temporary identity file path")
	}
	if cleanup != nil {
		cleanup()
	}
	if _, err := os.Stat(prepared.identityFile); !os.IsNotExist(err) {
		t.Fatalf("temporary identity file should be removed, stat err=%v", err)
	}
}

func TestSSHRunnerRejectsExternalIdentityFilePath(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := SSHDeploymentRequest{Host: "192.0.2.10", User: "root", Port: 22, Action: "check"}
	req.identityFile = keyPath
	if _, err := runner.BuildSSHArgs(req); err == nil {
		t.Fatal("external identity file path must not be accepted unless prepared from private_key")
	}
}

func TestSSHRunnerRejectsSymlinkIdentityFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "id_real")
	link := filepath.Join(dir, "id_link")
	if err := os.WriteFile(target, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	runner := NewSSHRunner(SSHRunnerOptions{})
	req := SSHDeploymentRequest{Host: "192.0.2.10", User: "root", Port: 22, Action: "check"}
	req.identityFile = link
	if _, err := runner.BuildSSHArgs(req); err == nil {
		t.Fatal("symlink identity file must be rejected")
	}
}

func TestSSHRunnerRejectsUnsafeHostAndCommand(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	for _, req := range []SSHDeploymentRequest{
		{Host: "192.0.2.10;rm -rf /", User: "root", Port: 22},
		{Host: "192.0.2.10", User: "root;id", Port: 22},
		{Host: "192.0.2.10", User: "root", Port: 70000},
		{Host: "192.0.2.10", User: "root", Port: 22, Action: "echo ok; rm -rf /"},
		{Host: "192.0.2.10", User: "root", Port: 22, Password: "secret"},
		{Host: "192.0.2.10", User: "root", Port: 22, SaveCredential: true},
	} {
		if _, err := runner.BuildSSHArgs(req); err == nil {
			t.Fatalf("expected unsafe request rejection: %+v", req)
		}
	}
}

func TestSSHRunnerDeployRequiresExplicitFixedAction(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	if _, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host: "192.0.2.10",
		User: "root",
		Port: 22,
	}); err == nil {
		t.Fatal("deploy must require an explicit non-check fixed action")
	}
}

func TestSSHRunnerOutputLimitWriter(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{w: &buf, limit: 4}
	n, err := w.Write([]byte("abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("n=%d, want 6", n)
	}
	if got := buf.String(); got != "abcd" {
		t.Fatalf("limited output=%q, want abcd", got)
	}
	if !w.Truncated() {
		t.Fatal("writer should report truncation")
	}
}
