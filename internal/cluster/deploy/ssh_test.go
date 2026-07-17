package deploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHDeploymentDoesNotPersistCredentialsByDefault(t *testing.T) {
	rec := NewMemoryAuditRecorder()
	runner := NewSSHRunner(SSHRunnerOptions{Audit: rec})
	if err := runner.Prepare(context.Background(), SSHDeploymentRequest{
		Host:           "192.0.2.10",
		User:           "root",
		Port:           22,
		Password:       "secret",
		SaveCredential: false,
	}); err != nil {
		t.Fatal(err)
	}
	if runner.StoredCredentialCount() != 0 {
		t.Fatal("temporary SSH deployment must not persist credentials")
	}
	if rec.Contains("secret") {
		t.Fatal("password must not appear in audit records")
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

func TestSSHRunnerRejectsUnknownHostKeyByDefault(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	if _, err := runner.hostKeyCallback(SSHDeploymentRequest{}); err == nil || !strings.Contains(err.Error(), "fingerprint confirmation is required") {
		t.Fatalf("expected unknown host key to fail closed, got %v", err)
	}
}

func TestInstallBackupUsesChecksumPrefixNotTaskID(t *testing.T) {
	sum := strings.Repeat("a", 64)
	command := installCommand(3, sum, "deploy-12345678-1234-1234-1234-123456789abc")
	// Backup names use a hex prefix of the local binary checksum only — never operator task IDs.
	if !strings.Contains(command, ".bak."+sum[:16]) {
		t.Fatalf("backup must use checksum prefix: %s", command)
	}
	if strings.Contains(command, "deploy-12345678") {
		t.Fatal("install backup must not embed operator task IDs into the remote shell")
	}
	if strings.Contains(command, "date -u +%Y%m%d%H%M%S") {
		t.Fatal("install backup must not use a timestamp-only name")
	}
}

func TestSSHRunnerPasswordAuthExecutesFixedCheck(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "ok\n"})
	rec := NewMemoryAuditRecorder()
	runner := NewSSHRunner(SSHRunnerOptions{Audit: rec, Timeout: 5 * time.Second, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	result, err := runner.Check(context.Background(), SSHDeploymentRequest{
		Host:          server.host,
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Message != "ok" {
		t.Fatalf("check result=%+v", result)
	}
	if strings.Contains(strings.Join(result.Command, " "), "secret") || rec.Contains("secret") {
		t.Fatal("password must not appear in command preview or audit records")
	}
	if command := server.lastCommand(); !strings.Contains(command, "CheeseWAF deployment prerequisites OK") {
		t.Fatalf("command=%q, want deployment prerequisite check", command)
	}
}

func TestSSHRunnerPrivateKeyAuthExecutesFixedDeploy(t *testing.T) {
	clientKey, privateKeyPEM := generateSSHPrivateKey(t)
	server := startTestSSHServer(t, testSSHServerOptions{AuthorizedKey: clientKey.PublicKey(), Output: "CheeseWAF dev\n"})
	rec := NewMemoryAuditRecorder()
	tmp := t.TempDir()
	binary := writeTestDeployBinary(t, tmp, "cheesewaf-test-binary")
	t.Setenv("CHEESEWAF_DEPLOY_BINARY", binary)
	runner := NewSSHRunner(SSHRunnerOptions{Audit: rec, Timeout: 5 * time.Second, KnownHosts: filepath.Join(tmp, "known_hosts")})
	result, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host:          server.host,
		User:          "root",
		Port:          server.port,
		PrivateKey:    privateKeyPEM,
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
		Action:        "install",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || strings.TrimSpace(result.Output) != "CheeseWAF dev" {
		t.Fatalf("deploy result=%+v", result)
	}
	if containsCheeseWAFTempKey(t, tmp) {
		t.Fatal("private key flow must not create temporary ssh key files")
	}
	if rec.Contains(privateKeyPEM) {
		t.Fatal("private key content must not appear in audit records")
	}
	exec := server.lastExec()
	if !strings.Contains(exec.command, "install -m 0755") || !strings.Contains(exec.command, "/usr/local/bin/cheesewaf") {
		t.Fatalf("command=%q, want fixed install command", exec.command)
	}
	if string(exec.stdin) != "cheesewaf-test-binary" {
		t.Fatalf("uploaded stdin=%q, want deploy binary content", exec.stdin)
	}
}

func TestSSHRunnerExecutesFixedRollbackInstall(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "CheeseWAF previous\n"})
	runner := NewSSHRunner(SSHRunnerOptions{Timeout: 5 * time.Second, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	result, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host:          server.host,
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
		Action:        actionRollbackInstall,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || strings.TrimSpace(result.Output) != "CheeseWAF previous" {
		t.Fatalf("rollback result=%+v", result)
	}
	exec := server.lastExec()
	for _, want := range []string{`"$target".bak.*`, `install -m 0755 "$latest" "$target"`, `CheeseWAF restored from`} {
		if !strings.Contains(exec.command, want) {
			t.Fatalf("rollback command missing %q: %s", want, exec.command)
		}
	}
	if len(exec.stdin) != 0 {
		t.Fatalf("rollback action must not upload stdin, got %q", exec.stdin)
	}
}

func TestSSHRunnerRejectsHostKeyMismatch(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "ok\n"})
	otherKey, _ := generateSSHPrivateKey(t)
	runner := NewSSHRunner(SSHRunnerOptions{Timeout: 5 * time.Second, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	_, err := runner.Check(context.Background(), SSHDeploymentRequest{
		Host:          server.host,
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(otherKey.PublicKey()),
	})
	if err == nil {
		t.Fatal("host key mismatch must fail")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("error must not expose password")
	}
}

func TestSSHRunnerRejectsKnownHostsChangedKey(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "ok\n"})
	otherKey, _ := generateSSHPrivateKey(t)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := appendKnownHost(knownHosts, []string{net.JoinHostPort(server.host, strconv.Itoa(server.port))}, otherKey.PublicKey()); err != nil {
		t.Fatal(err)
	}
	runner := NewSSHRunner(SSHRunnerOptions{Timeout: 5 * time.Second, KnownHosts: knownHosts})
	_, err := runner.Check(context.Background(), SSHDeploymentRequest{
		Host:     server.host,
		User:     "root",
		Port:     server.port,
		Password: "secret",
	})
	if err == nil {
		t.Fatal("changed known_hosts key must fail")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("error must not expose password")
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
		t.Fatal("external identity file path must not be accepted")
	}
}

func TestSSHRunnerRejectsUnsafeHostAndCommand(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	for _, req := range []SSHDeploymentRequest{
		{Host: "192.0.2.10;rm -rf /", User: "root", Port: 22},
		{Host: "192.0.2.10", User: "root;id", Port: 22},
		{Host: "192.0.2.10", User: "root", Port: 70000},
		{Host: "192.0.2.10", User: "root", Port: 22, Action: "echo ok; rm -rf /"},
		{Host: "192.0.2.10", User: "root", Port: 22, Password: "secret", PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----"},
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

func TestSSHRunnerCompensationPlanUsesTruthfulActions(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	plan := runner.CompensationPlan(SSHDeploymentRequest{Action: actionRestartService})
	if !plan.Applicable {
		t.Fatalf("restart-service compensation should be applicable: %+v", plan)
	}
	if plan.Action != compensationStartService {
		t.Fatalf("restart-service compensation action=%q, want %q", plan.Action, compensationStartService)
	}
	if command := compensationCommandForAction(plan.Action); command != "systemctl start cheesewaf" {
		t.Fatalf("restart-service compensation command=%q", command)
	}
	if strings.Contains(strings.ToLower(plan.Message), "rollback") {
		t.Fatalf("restart-service compensation must not imply rollback: %q", plan.Message)
	}
}

func TestSSHRunnerInstallCompensationIsNotApplicable(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	plan := runner.CompensationPlan(SSHDeploymentRequest{Action: actionInstall})
	if plan.Applicable || plan.Action != compensationNone {
		t.Fatalf("install compensation plan=%+v, want not applicable none", plan)
	}
	result, err := runner.Compensate(context.Background(), SSHDeploymentRequest{Action: actionInstall}, fmt.Errorf("install failed"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Attempted || result.Status != CompensationStatusNotApplicable || result.Action != compensationNone {
		t.Fatalf("install compensation result=%+v, want not_applicable without attempt", result)
	}
	if strings.Contains(strings.ToLower(result.Message), "rollback") {
		t.Fatalf("install compensation must not imply rollback: %q", result.Message)
	}
}

func TestSSHRunnerRollbackInstallCompensationIsNotApplicable(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{})
	plan := runner.CompensationPlan(SSHDeploymentRequest{Action: actionRollbackInstall})
	if plan.Applicable || plan.Action != compensationNone {
		t.Fatalf("rollback compensation plan=%+v, want not applicable none", plan)
	}
	result, err := runner.Compensate(context.Background(), SSHDeploymentRequest{Action: actionRollbackInstall}, fmt.Errorf("rollback failed"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Attempted || result.Status != CompensationStatusNotApplicable || result.Action != compensationNone {
		t.Fatalf("rollback compensation result=%+v, want not_applicable without attempt", result)
	}
}

func TestSSHRunnerOutputLimit(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "abcdef"})
	binary := writeTestDeployBinary(t, t.TempDir(), "abcdef")
	t.Setenv("CHEESEWAF_DEPLOY_BINARY", binary)
	runner := NewSSHRunner(SSHRunnerOptions{Timeout: 5 * time.Second, OutputLimit: 4, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	result, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host:          server.host,
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
		Action:        "install",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Output != "abcd" || !result.OutputTruncated {
		t.Fatalf("output=%q truncated=%v", result.Output, result.OutputTruncated)
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

type testSSHServerOptions struct {
	Password      string
	AuthorizedKey ssh.PublicKey
	Output        string
}

type testSSHServer struct {
	host    string
	port    int
	hostKey ssh.Signer
	command chan testSSHExec
}

type testSSHExec struct {
	command string
	stdin   []byte
}

func (s *testSSHServer) lastCommand() string {
	exec := s.lastExec()
	return exec.command
}

func (s *testSSHServer) lastExec() testSSHExec {
	select {
	case exec := <-s.command:
		return exec
	default:
		return testSSHExec{}
	}
}

func startTestSSHServer(t *testing.T, opts testSSHServerOptions) *testSSHServer {
	t.Helper()
	hostKey, _ := generateSSHPrivateKey(t)
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "root" && opts.Password != "" && string(password) == opts.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "root" && opts.AuthorizedKey != nil && bytes.Equal(key.Marshal(), opts.AuthorizedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	config.AddHostKey(hostKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &testSSHServer{
		host:    "127.0.0.1",
		port:    listener.Addr().(*net.TCPAddr).Port,
		hostKey: hostKey,
		command: make(chan testSSHExec, 4),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(conn, config, opts.Output, server.command)
		}
	}()
	return server
}

func handleTestSSHConn(conn net.Conn, config *ssh.ServerConfig, output string, commands chan<- testSSHExec) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				switch req.Type {
				case "exec":
					var payload struct {
						Command string
					}
					if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
						_ = req.Reply(false, nil)
						continue
					}
					_ = req.Reply(true, nil)
					stdinCh := make(chan []byte, 1)
					go func() {
						stdin, _ := io.ReadAll(channel)
						stdinCh <- stdin
					}()
					_, _ = channel.Write([]byte(output))
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					var stdin []byte
					select {
					case stdin = <-stdinCh:
					case <-time.After(100 * time.Millisecond):
					}
					commands <- testSSHExec{command: payload.Command, stdin: stdin}
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

func generateSSHPrivateKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(pemBytes)
}

func containsCheeseWAFTempKey(t *testing.T, dir string) bool {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "cheesewaf-ssh-key-*.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches) > 0
}

func writeTestDeployBinary(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "cheesewaf-test-bin")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
