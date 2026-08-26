package deploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
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

func TestInstallPublishesOnlyTheExactPreviousGenerationAfterVerification(t *testing.T) {
	sum := strings.Repeat("a", 64)
	command := installCommand(3, sum, "deploy-12345678-1234-1234-1234-123456789abc")
	for _, want := range []string{
		`previous="${target}.bak.previous"`,
		`backup=$(mktemp "${target}.backup.pending.XXXXXX")`,
		`mv -f "$candidate" "$target"`,
		`mv -f "$backup" "$previous"`,
		`cp -p "$backup" "$target"`,
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("install command missing %q: %s", want, command)
		}
	}
	for _, forbidden := range []string{"deploy-12345678", ".bak." + sum[:16], `"$target".bak.*`, "latest"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("install command must not contain %q: %s", forbidden, command)
		}
	}
	targetVerification := strings.LastIndex(command, `"$target" --version`)
	publishPrevious := strings.Index(command, `mv -f "$backup" "$previous"`)
	if targetVerification < 0 || publishPrevious < 0 || publishPrevious < targetVerification {
		t.Fatalf("previous generation must be published only after target verification: %s", command)
	}
}

func TestSSHRunnerPasswordAuthExecutesFixedCheck(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "ok\n"})
	rec := NewMemoryAuditRecorder()
	runner := newRedirectedTestSSHRunner(server, SSHRunnerOptions{Audit: rec, Timeout: 5 * time.Second, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	result, err := runner.Check(context.Background(), SSHDeploymentRequest{
		Host:          "node.example.com",
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
	runner := newRedirectedTestSSHRunner(server, SSHRunnerOptions{Audit: rec, Timeout: 5 * time.Second, KnownHosts: filepath.Join(tmp, "known_hosts")})
	result, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host:          "node.example.com",
		User:          "root",
		Port:          server.port,
		PrivateKey:    privateKeyPEM,
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
		Action:        "install",
		ResolvedIPs:   []string{"8.8.8.8"},
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
	runner := newRedirectedTestSSHRunner(server, SSHRunnerOptions{Timeout: 5 * time.Second, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	result, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host:          "node.example.com",
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
		Action:        actionRollbackInstall,
		ResolvedIPs:   []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || strings.TrimSpace(result.Output) != "CheeseWAF previous" {
		t.Fatalf("rollback result=%+v", result)
	}
	exec := server.lastExec()
	for _, want := range []string{
		`previous="${target}.bak.previous"`,
		`install -m 0755 "$previous" "$candidate"`,
		`mv -f "$candidate" "$target"`,
		`mv -f "$current" "$previous"`,
		`cp -p "$current" "$target"`,
		`CheeseWAF restored from "$previous"`,
	} {
		if !strings.Contains(exec.command, want) {
			t.Fatalf("rollback command missing %q: %s", want, exec.command)
		}
	}
	for _, forbidden := range []string{`"$target".bak.*`, "latest", "pre-rollback", "date -u"} {
		if strings.Contains(exec.command, forbidden) {
			t.Fatalf("rollback command must not contain %q: %s", forbidden, exec.command)
		}
	}
	if len(exec.stdin) != 0 {
		t.Fatalf("rollback action must not upload stdin, got %q", exec.stdin)
	}
}

func TestInstallAndRollbackUseTheSameExactPreviousGeneration(t *testing.T) {
	install := installCommand(3, strings.Repeat("b", 64))
	rollback := rollbackInstallCommand()
	const previous = `previous="${target}.bak.previous"`
	for name, command := range map[string]string{"install": install, "rollback": rollback} {
		if strings.Count(command, previous) != 1 {
			t.Fatalf("%s command must declare one exact previous generation: %s", name, command)
		}
		if strings.Contains(command, `"$target".bak.*`) || strings.Contains(command, "latest") {
			t.Fatalf("%s command must not discover backups by wildcard: %s", name, command)
		}
	}
	targetVerification := strings.LastIndex(rollback, `"$target" --version`)
	preserveCurrent := strings.Index(rollback, `mv -f "$current" "$previous"`)
	if targetVerification < 0 || preserveCurrent < 0 || preserveCurrent < targetVerification {
		t.Fatalf("rollback must preserve current as previous only after target verification: %s", rollback)
	}
	preview, err := remoteCommandPreviewForAction(actionRollbackInstall)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview, defaultInstallTarget+".bak.previous") || strings.Contains(preview, "newest") || strings.Contains(preview, ".bak.*") {
		t.Fatalf("rollback preview must name the exact previous generation: %q", preview)
	}
}

func TestInstallAndRollbackExchangeTheExactPreviousGeneration(t *testing.T) {
	shell := deploymentTestShell(t)
	target := filepath.Join(t.TempDir(), "cheesewaf")
	previous := target + ".bak.previous"
	currentBinary := []byte("#!/bin/sh\nprintf 'current\\n'\n")
	previousBinary := []byte("#!/bin/sh\nprintf 'previous\\n'\n")
	replacementBinary := []byte("#!/bin/sh\nprintf 'replacement\\n'\n")
	writeTestShellBinary(t, target, currentBinary)
	writeTestShellBinary(t, previous, previousBinary)

	if output, err := runDeploymentTestScript(shell, target, installCommand(int64(len(replacementBinary)), checksumHex(replacementBinary)), replacementBinary); err != nil {
		t.Fatalf("install script failed: %v\n%s", err, output)
	}
	assertFileContent(t, target, replacementBinary)
	assertFileContent(t, previous, currentBinary)
	assertNoDeploymentTemps(t, target)

	if output, err := runDeploymentTestScript(shell, target, rollbackInstallCommand(), nil); err != nil {
		t.Fatalf("rollback script failed: %v\n%s", err, output)
	}
	assertFileContent(t, target, currentBinary)
	assertFileContent(t, previous, replacementBinary)
	assertNoDeploymentTemps(t, target)
}

func TestInstallVerificationFailureRestoresCurrentAndPreservesPrevious(t *testing.T) {
	shell := deploymentTestShell(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "cheesewaf")
	previous := target + ".bak.previous"
	currentBinary := []byte("#!/bin/sh\nprintf 'current\\n'\n")
	previousBinary := []byte("#!/bin/sh\nprintf 'previous\\n'\n")
	writeTestShellBinary(t, target, currentBinary)
	writeTestShellBinary(t, previous, previousBinary)
	counter := filepath.Join(dir, "install-runs")
	failingBinary := failOnThirdRunBinary(counter)

	if output, err := runDeploymentTestScript(shell, target, installCommand(int64(len(failingBinary)), checksumHex(failingBinary)), failingBinary); err == nil {
		t.Fatalf("install must fail when the installed target fails verification:\n%s", output)
	}
	assertFileContent(t, counter, []byte("3"))
	assertFileContent(t, target, currentBinary)
	assertFileContent(t, previous, previousBinary)
	assertNoDeploymentTemps(t, target)
}

func TestRollbackVerificationFailureRestoresCurrentAndPreservesPrevious(t *testing.T) {
	shell := deploymentTestShell(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "cheesewaf")
	previous := target + ".bak.previous"
	currentBinary := []byte("#!/bin/sh\nprintf 'current\\n'\n")
	counter := filepath.Join(dir, "rollback-runs")
	failingPrevious := failOnThirdRunBinary(counter)
	writeTestShellBinary(t, target, currentBinary)
	writeTestShellBinary(t, previous, failingPrevious)

	if output, err := runDeploymentTestScript(shell, target, rollbackInstallCommand(), nil); err == nil {
		t.Fatalf("rollback must fail when the restored target fails verification:\n%s", output)
	}
	assertFileContent(t, counter, []byte("3"))
	assertFileContent(t, target, currentBinary)
	assertFileContent(t, previous, failingPrevious)
	assertNoDeploymentTemps(t, target)
}

func deploymentTestShell(t *testing.T) string {
	t.Helper()
	if shell, err := exec.LookPath("sh"); err == nil {
		return shell
	}
	for _, shell := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "usr", "bin", "sh.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"),
	} {
		if info, err := os.Stat(shell); err == nil && !info.IsDir() {
			return shell
		}
	}
	t.Skip("POSIX shell unavailable")
	return ""
}

func runDeploymentTestScript(shell, target, command string, input []byte) (string, error) {
	targetAssignment := "target=" + shellSingleQuote(filepath.ToSlash(target))
	command = strings.Replace(command, "target="+defaultInstallTarget, targetAssignment, 1)
	cmd := exec.Command(shell, "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Dir(shell)+string(os.PathListSeparator)+os.Getenv("PATH"))
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func checksumHex(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:])
}

func failOnThirdRunBinary(counterPath string) []byte {
	return []byte("#!/bin/sh\n" +
		"counter=" + shellSingleQuote(filepath.ToSlash(counterPath)) + "\n" +
		"count=0\n" +
		"if [ -f \"$counter\" ]; then count=$(cat \"$counter\"); fi\n" +
		"count=$((count + 1))\n" +
		"printf '%s' \"$count\" > \"$counter\"\n" +
		"if [ \"$count\" -ge 3 ]; then exit 1; fi\n" +
		"printf 'version ok\\n'\n")
}

func writeTestShellBinary(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s content=%q, want %q", path, got, want)
	}
}

func assertNoDeploymentTemps(t *testing.T, target string) {
	t.Helper()
	for _, pattern := range []string{
		target + ".backup.pending.*",
		target + ".install.pending.*",
		target + ".rollback.pending.*",
		target + ".rollback-current.*",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("deployment left temporary files matching %q: %v", pattern, matches)
		}
	}
}

func TestSSHRunnerRejectsHostKeyMismatch(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "ok\n"})
	otherKey, _ := generateSSHPrivateKey(t)
	runner := newRedirectedTestSSHRunner(server, SSHRunnerOptions{Timeout: 5 * time.Second, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	_, err := runner.Check(context.Background(), SSHDeploymentRequest{
		Host:          "node.example.com",
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
	if !strings.Contains(plan.Message, "exact previous generation") || strings.Contains(plan.Message, "newest") || strings.Contains(plan.Message, ".bak.*") {
		t.Fatalf("rollback compensation message must describe the exact previous generation: %q", plan.Message)
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
	runner := newRedirectedTestSSHRunner(server, SSHRunnerOptions{Timeout: 5 * time.Second, OutputLimit: 4, KnownHosts: filepath.Join(t.TempDir(), "known_hosts")})
	result, err := runner.Deploy(context.Background(), SSHDeploymentRequest{
		Host:          "node.example.com",
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
		Action:        "install",
		ResolvedIPs:   []string{"8.8.8.8"},
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

func newRedirectedTestSSHRunner(server *testSSHServer, opts SSHRunnerOptions) *SSHRunner {
	opts.Resolver = &staticTargetResolver{answers: map[string][]netip.Addr{
		"node.example.com": {netip.MustParseAddr("8.8.8.8")},
	}}
	opts.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server.host, strconv.Itoa(server.port)))
	}
	return NewSSHRunner(opts)
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
