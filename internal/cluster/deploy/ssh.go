package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHDeploymentRequest struct {
	Host           string `json:"host"`
	User           string `json:"user"`
	Port           int    `json:"port"`
	Password       string `json:"password,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	HostKeySHA256  string `json:"host_key_sha256,omitempty"`
	identityFile   string
	SaveCredential bool   `json:"save_credential"`
	Action         string `json:"action,omitempty"`
	TaskID         string `json:"-"`
}

type CheckResult struct {
	OK        bool      `json:"ok"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	Port      int       `json:"port"`
	Command   []string  `json:"command"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

type DeployResult struct {
	OK              bool      `json:"ok"`
	Host            string    `json:"host"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	Output          string    `json:"output,omitempty"`
	OutputTruncated bool      `json:"output_truncated,omitempty"`
}

type CompensationPlan struct {
	Applicable bool   `json:"applicable"`
	Action     string `json:"action,omitempty"`
	Message    string `json:"message,omitempty"`
}

type CompensationResult struct {
	Attempted       bool       `json:"attempted"`
	Status          string     `json:"status"`
	Action          string     `json:"action,omitempty"`
	Message         string     `json:"message,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	Output          string     `json:"output,omitempty"`
	OutputTruncated bool       `json:"output_truncated,omitempty"`
	Error           string     `json:"error,omitempty"`
}

type AuditRecorder interface {
	Record(action string, fields map[string]string)
}

type MemoryAuditRecorder struct {
	mu      sync.Mutex
	records []string
}

func NewMemoryAuditRecorder() *MemoryAuditRecorder {
	return &MemoryAuditRecorder{}
}

func (r *MemoryAuditRecorder) Record(action string, fields map[string]string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	parts := []string{action}
	for key, value := range fields {
		parts = append(parts, key+"="+value)
	}
	r.records = append(r.records, strings.Join(parts, " "))
}

func (r *MemoryAuditRecorder) Contains(needle string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.records {
		if strings.Contains(record, needle) {
			return true
		}
	}
	return false
}

type SSHRunnerOptions struct {
	Audit       AuditRecorder
	Timeout     time.Duration
	OutputLimit int
	KnownHosts  string
}

type SSHRunner struct {
	audit             AuditRecorder
	timeout           time.Duration
	outputLimit       int
	knownHostsPath    string
	storedCredentials map[string]string
}

func NewSSHRunner(opts SSHRunnerOptions) *SSHRunner {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	outputLimit := opts.OutputLimit
	if outputLimit <= 0 {
		outputLimit = 64 * 1024
	}
	return &SSHRunner{audit: opts.Audit, timeout: timeout, outputLimit: outputLimit, knownHostsPath: strings.TrimSpace(opts.KnownHosts), storedCredentials: map[string]string{}}
}

func (r *SSHRunner) Prepare(_ context.Context, req SSHDeploymentRequest) error {
	prepared, err := r.prepareRequest(context.Background(), req)
	if err != nil {
		return err
	}
	if _, err := r.BuildSSHArgs(prepared); err != nil {
		return err
	}
	r.record("ssh_deploy.prepare", prepared, nil)
	return nil
}

func (r *SSHRunner) Check(ctx context.Context, req SSHDeploymentRequest) (CheckResult, error) {
	req.Action = actionCheck
	prepared, err := r.prepareRequest(ctx, req)
	if err != nil {
		return CheckResult{}, err
	}
	args, err := r.BuildSSHArgs(prepared)
	if err != nil {
		return CheckResult{}, err
	}
	started := time.Now().UTC()
	output, truncated, err := r.runRemoteCommand(ctx, prepared)
	fields := map[string]string{"ok": strconv.FormatBool(err == nil)}
	if err != nil {
		fields["error"] = sanitizeTaskText(err.Error(), prepared)
	}
	r.record("ssh_deploy.check", prepared, fields)
	message := sanitizeTaskText(outputStatusMessage(output, truncated), prepared)
	if err != nil {
		return CheckResult{
			OK:        false,
			Host:      strings.TrimSpace(prepared.Host),
			User:      strings.TrimSpace(prepared.User),
			Port:      normalizedSSHPort(prepared.Port),
			Command:   append([]string{"ssh"}, redactedSSHArgs(args)...),
			Message:   message,
			CheckedAt: started,
		}, sanitizeSSHError(err, prepared)
	}
	return CheckResult{
		OK:        true,
		Host:      strings.TrimSpace(prepared.Host),
		User:      strings.TrimSpace(prepared.User),
		Port:      normalizedSSHPort(prepared.Port),
		Command:   append([]string{"ssh"}, redactedSSHArgs(args)...),
		Message:   message,
		CheckedAt: started,
	}, nil
}

func (r *SSHRunner) Deploy(ctx context.Context, req SSHDeploymentRequest) (DeployResult, error) {
	if strings.TrimSpace(req.Action) == "" || strings.TrimSpace(req.Action) == actionCheck {
		return DeployResult{}, fmt.Errorf("deploy action must be install, rollback-install, or restart-service")
	}
	prepared, err := r.prepareRequest(ctx, req)
	if err != nil {
		return DeployResult{}, err
	}
	started := time.Now().UTC()
	output, truncated, err := r.runRemoteCommand(ctx, prepared)
	result := DeployResult{
		OK:              err == nil,
		Host:            strings.TrimSpace(prepared.Host),
		StartedAt:       started,
		FinishedAt:      time.Now().UTC(),
		Output:          sanitizeTaskText(output, prepared),
		OutputTruncated: truncated,
	}
	fields := map[string]string{"ok": strconv.FormatBool(result.OK)}
	if err != nil {
		fields["error"] = sanitizeTaskText(err.Error(), prepared)
	}
	r.record("ssh_deploy.run", prepared, fields)
	if err != nil {
		return result, sanitizeSSHError(err, prepared)
	}
	return result, nil
}

func (r *SSHRunner) CompensationPlan(req SSHDeploymentRequest) CompensationPlan {
	switch strings.TrimSpace(req.Action) {
	case actionRestartService:
		return CompensationPlan{
			Applicable: true,
			Action:     compensationStartService,
			Message:    "Attempt to start the CheeseWAF service after restart failure",
		}
	case actionInstall:
		return CompensationPlan{
			Applicable: false,
			Action:     compensationNone,
			Message:    "The install action performs inline backup and restore when possible; no separate compensation action is available after the SSH session ends",
		}
	case actionRollbackInstall:
		return CompensationPlan{
			Applicable: false,
			Action:     compensationNone,
			Message:    "The rollback action restores the newest binary backup directly; no separate compensation action is available after the SSH session ends",
		}
	default:
		return CompensationPlan{
			Applicable: false,
			Action:     compensationNone,
			Message:    "No compensation action is defined for this deployment action",
		}
	}
}

func (r *SSHRunner) Compensate(ctx context.Context, req SSHDeploymentRequest, cause error) (CompensationResult, error) {
	plan := r.CompensationPlan(req)
	if !plan.Applicable {
		return CompensationResult{
			Attempted: false,
			Status:    CompensationStatusNotApplicable,
			Action:    plan.Action,
			Message:   plan.Message,
		}, nil
	}
	prepared, err := r.prepareRequest(ctx, req)
	if err != nil {
		return CompensationResult{
			Attempted: false,
			Status:    CompensationStatusFailed,
			Action:    plan.Action,
			Message:   "Compensation could not start because the original SSH request is no longer valid",
			Error:     sanitizeTaskText(err.Error(), req),
		}, err
	}
	started := time.Now().UTC()
	output, truncated, err := r.runRemoteCommandRaw(ctx, prepared, compensationCommandForAction(plan.Action))
	finished := time.Now().UTC()
	result := CompensationResult{
		Attempted:       true,
		Status:          CompensationStatusSucceeded,
		Action:          plan.Action,
		Message:         plan.Message,
		StartedAt:       &started,
		FinishedAt:      &finished,
		Output:          sanitizeTaskText(output, prepared),
		OutputTruncated: truncated,
	}
	fields := map[string]string{
		"action": plan.Action,
		"ok":     strconv.FormatBool(err == nil),
	}
	if cause != nil {
		fields["cause"] = sanitizeTaskText(cause.Error(), prepared)
	}
	if err != nil {
		result.Status = CompensationStatusFailed
		result.Error = sanitizeTaskText(err.Error(), prepared)
		fields["error"] = result.Error
	}
	r.record("ssh_deploy.compensate", prepared, fields)
	if err != nil {
		return result, sanitizeSSHError(err, prepared)
	}
	return result, nil
}

func (r *SSHRunner) BuildSSHArgs(req SSHDeploymentRequest) ([]string, error) {
	host := strings.TrimSpace(req.Host)
	user := strings.TrimSpace(req.User)
	port := normalizedSSHPort(req.Port)
	if err := validateHostAddress(host); err != nil {
		return nil, fmt.Errorf("ssh host invalid: %w", err)
	}
	if !safeIdentifier.MatchString(user) {
		return nil, fmt.Errorf("ssh user must be a safe identifier")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("ssh port must be between 1 and 65535")
	}
	if req.SaveCredential {
		return nil, fmt.Errorf("saving SSH credentials is not supported by the temporary runner")
	}
	if strings.TrimSpace(req.Password) != "" && strings.TrimSpace(req.PrivateKey) != "" {
		return nil, fmt.Errorf("provide either ssh password or private_key, not both")
	}
	identityFile := strings.TrimSpace(req.identityFile)
	if identityFile != "" {
		return nil, fmt.Errorf("server-side identity_file paths are not accepted by the SSH deployment API")
	}
	if strings.TrimSpace(req.PrivateKey) != "" {
		if _, err := parsePrivateKey(req.PrivateKey); err != nil {
			return nil, err
		}
	}
	command, err := remoteCommandPreviewForAction(req.Action)
	if err != nil {
		return nil, err
	}
	args := []string{"-p", strconv.Itoa(port)}
	switch {
	case strings.TrimSpace(req.PrivateKey) != "":
		args = append(args, "-o", "PreferredAuthentications=publickey")
	case strings.TrimSpace(req.Password) != "":
		args = append(args, "-o", "PreferredAuthentications=password")
	default:
		args = append(args, "-o", "PreferredAuthentications=publickey")
	}
	args = append(args, user+"@"+host, command)
	return args, nil
}

func (r *SSHRunner) prepareRequest(_ context.Context, req SSHDeploymentRequest) (SSHDeploymentRequest, error) {
	req.Host = strings.TrimSpace(req.Host)
	req.User = strings.TrimSpace(req.User)
	req.Password = strings.TrimSpace(req.Password)
	req.PrivateKey = strings.TrimSpace(req.PrivateKey)
	req.HostKeySHA256 = normalizeHostKeyFingerprint(req.HostKeySHA256)
	req.Action = strings.TrimSpace(req.Action)
	if _, err := r.BuildSSHArgs(req); err != nil {
		return SSHDeploymentRequest{}, err
	}
	return req, nil
}

func (r *SSHRunner) runRemoteCommand(ctx context.Context, req SSHDeploymentRequest) (string, bool, error) {
	if strings.TrimSpace(req.Action) == actionInstall {
		return r.runRemoteInstall(ctx, req)
	}
	command, err := remoteCommandForAction(req.Action)
	if err != nil {
		return "", false, err
	}
	return r.runRemoteCommandRaw(ctx, req, command)
}

func (r *SSHRunner) runRemoteCommandRaw(ctx context.Context, req SSHDeploymentRequest, command string) (string, bool, error) {
	return r.runRemoteCommandWithInput(ctx, req, command, nil)
}

func (r *SSHRunner) runRemoteCommandWithInput(ctx context.Context, req SSHDeploymentRequest, command string, input io.Reader) (string, bool, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", false, fmt.Errorf("remote command is required")
	}
	cmdCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	client, err := r.connect(cmdCtx, req)
	if err != nil {
		return "", false, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", false, fmt.Errorf("open ssh session: %w", err)
	}
	defer session.Close()

	var output bytes.Buffer
	limited := &limitWriter{w: &output, limit: r.outputLimit}
	session.Stdout = limited
	session.Stderr = limited
	if input != nil {
		session.Stdin = input
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-cmdCtx.Done():
			_ = client.Close()
		case <-done:
		}
	}()
	// Only fixed / builder-validated shell scripts may execute remotely.
	trusted, err := trustedRemoteShell(command)
	if err != nil {
		close(done)
		return "", false, err
	}
	err = session.Run(trusted)
	close(done)
	if cmdCtx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("ssh deployment timed out after %s", r.timeout)
	}
	return output.String(), limited.Truncated(), err
}

func (r *SSHRunner) runRemoteInstall(ctx context.Context, req SSHDeploymentRequest) (string, bool, error) {
	source, err := openInstallBinary()
	if err != nil {
		return "", false, err
	}
	defer source.file.Close()
	return r.runRemoteCommandWithInput(ctx, req, installCommand(source.size, source.sha256, req.TaskID), source.file)
}

func (r *SSHRunner) connect(ctx context.Context, req SSHDeploymentRequest) (*ssh.Client, error) {
	config, err := r.clientConfig(req)
	if err != nil {
		return nil, err
	}
	host := strings.TrimSpace(req.Host)
	port := normalizedSSHPort(req.Port)
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect ssh %s: %w", address, err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("authenticate ssh %s: %w", address, err)
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

func (r *SSHRunner) clientConfig(req SSHDeploymentRequest) (*ssh.ClientConfig, error) {
	auth, err := authMethods(req)
	if err != nil {
		return nil, err
	}
	callback, err := r.hostKeyCallback(req)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            strings.TrimSpace(req.User),
		Auth:            auth,
		HostKeyCallback: callback,
		Timeout:         r.timeout,
	}, nil
}

func authMethods(req SSHDeploymentRequest) ([]ssh.AuthMethod, error) {
	password := strings.TrimSpace(req.Password)
	privateKey := strings.TrimSpace(req.PrivateKey)
	if password != "" && privateKey != "" {
		return nil, fmt.Errorf("provide either ssh password or private_key, not both")
	}
	if password != "" {
		return []ssh.AuthMethod{ssh.Password(password)}, nil
	}
	if privateKey != "" {
		signer, err := parsePrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	signers, err := sshAgentSigners()
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("ssh credentials are required: provide a one-time password, a one-time private_key, or configure SSH_AUTH_SOCK for the service user")
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

func parsePrivateKey(value string) (ssh.Signer, error) {
	key := strings.TrimSpace(value)
	if !looksLikePrivateKey(key) {
		return nil, fmt.Errorf("private_key must be an OpenSSH or PEM private key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("private_key is not a usable SSH private key")
	}
	return signer, nil
}

func sshAgentSigners() ([]ssh.Signer, error) {
	socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socket == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect SSH agent: %w", err)
	}
	defer conn.Close()
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		return nil, fmt.Errorf("read SSH agent keys: %w", err)
	}
	return signers, nil
}

func (r *SSHRunner) hostKeyCallback(req SSHDeploymentRequest) (ssh.HostKeyCallback, error) {
	expected := normalizeHostKeyFingerprint(req.HostKeySHA256)
	if expected == "" {
		return nil, fmt.Errorf("ssh host key fingerprint confirmation is required")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		actual := normalizeHostKeyFingerprint(ssh.FingerprintSHA256(key))
		if actual != expected {
			return fmt.Errorf("ssh host key fingerprint mismatch")
		}
		return nil
	}, nil
}

func (r *SSHRunner) acceptNewKnownHostsCallback() (ssh.HostKeyCallback, error) {
	path, err := r.knownHostsFile()
	if err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		callback, err := knownhosts.New(path)
		if err != nil {
			if _, statErr := os.Stat(path); statErr != nil && os.IsNotExist(statErr) {
				return appendKnownHost(path, knownHostAddresses(hostname, remote), key)
			}
			return fmt.Errorf("ssh known_hosts is unavailable")
		}
		err = callback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
			return fmt.Errorf("ssh host key verification failed")
		}
		return appendKnownHost(path, knownHostAddresses(hostname, remote), key)
	}, nil
}

func (r *SSHRunner) knownHostsFile() (string, error) {
	if path := strings.TrimSpace(r.knownHostsPath); path != "" {
		if strings.ContainsAny(path, "\x00\r\n") {
			return "", fmt.Errorf("known_hosts path contains unsupported characters")
		}
		return filepath.Clean(path), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("user home unavailable")
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

func appendKnownHost(path string, addresses []string, key ssh.PublicKey) error {
	if len(addresses) == 0 {
		return fmt.Errorf("ssh host address is unavailable")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("prepare known_hosts directory: %w", err)
	}
	line := knownhosts.Line(addresses, key)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open known_hosts: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	return nil
}

func knownHostAddresses(hostname string, remote net.Addr) []string {
	seen := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		seen[value] = struct{}{}
	}
	add(hostname)
	if host, port, err := net.SplitHostPort(hostname); err == nil {
		add(host)
		add(net.JoinHostPort(host, port))
	}
	if remote != nil {
		add(remote.String())
		if host, port, err := net.SplitHostPort(remote.String()); err == nil {
			add(host)
			add(net.JoinHostPort(host, port))
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	return out
}

const (
	actionCheck              = "check"
	actionInstall            = "install"
	actionRollbackInstall    = "rollback-install"
	actionRestartService     = "restart-service"
	compensationNone         = "none"
	compensationStartService = "start-service"
	defaultInstallTarget     = "/usr/local/bin/cheesewaf"
	maxInstallBinarySize     = 512 * 1024 * 1024

	CompensationStatusNotApplicable = "not_applicable"
	CompensationStatusSucceeded     = "succeeded"
	CompensationStatusFailed        = "failed"
)

func remoteCommandForAction(action string) (string, error) {
	switch strings.TrimSpace(action) {
	case "", actionCheck:
		return remoteCheckCommand(), nil
	case actionInstall:
		return installCommand(0, strings.Repeat("0", 64)), nil
	case actionRollbackInstall:
		return rollbackInstallCommand(), nil
	case actionRestartService:
		return "systemctl restart cheesewaf", nil
	default:
		return "", fmt.Errorf("unsupported ssh deployment action")
	}
}

func remoteCommandPreviewForAction(action string) (string, error) {
	switch strings.TrimSpace(action) {
	case "", actionCheck:
		return remoteCheckCommand(), nil
	case actionInstall:
		return "upload current CheeseWAF binary, backup existing binary, install to " + defaultInstallTarget + ", then verify version", nil
	case actionRollbackInstall:
		return "restore the newest " + defaultInstallTarget + ".bak.* backup, then verify version", nil
	case actionRestartService:
		return "systemctl restart cheesewaf", nil
	default:
		return "", fmt.Errorf("unsupported ssh deployment action")
	}
}

func remoteCheckCommand() string {
	return strings.Join([]string{
		"command -v sh >/dev/null 2>&1",
		"command -v install >/dev/null 2>&1",
		"command -v mktemp >/dev/null 2>&1",
		"command -v chmod >/dev/null 2>&1",
		"command -v cp >/dev/null 2>&1",
		"command -v date >/dev/null 2>&1",
		"command -v wc >/dev/null 2>&1",
		"command -v tr >/dev/null 2>&1",
		"command -v sha256sum >/dev/null 2>&1",
		"command -v awk >/dev/null 2>&1",
		"test -d /usr/local/bin",
		"test -w /usr/local/bin",
		"echo CheeseWAF deployment prerequisites OK",
	}, " && ")
}

type installBinarySource struct {
	file   *os.File
	size   int64
	sha256 string
}

func openInstallBinary() (installBinarySource, error) {
	path := strings.TrimSpace(os.Getenv("CHEESEWAF_DEPLOY_BINARY"))
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			return installBinarySource{}, fmt.Errorf("install source binary is unavailable; set CHEESEWAF_DEPLOY_BINARY to a readable CheeseWAF binary")
		}
		path = executable
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return installBinarySource{}, fmt.Errorf("install source binary path contains unsupported characters")
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return installBinarySource{}, fmt.Errorf("install source binary is unavailable; set CHEESEWAF_DEPLOY_BINARY to a readable CheeseWAF binary")
	}
	if !info.Mode().IsRegular() {
		return installBinarySource{}, fmt.Errorf("install source binary must be a regular file")
	}
	if info.Size() <= 0 {
		return installBinarySource{}, fmt.Errorf("install source binary is empty")
	}
	if info.Size() > maxInstallBinarySize {
		return installBinarySource{}, fmt.Errorf("install source binary exceeds the safety limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return installBinarySource{}, fmt.Errorf("install source binary is unreadable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		return installBinarySource{}, fmt.Errorf("install source binary checksum failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return installBinarySource{}, fmt.Errorf("install source binary could not be rewound")
	}
	return installBinarySource{
		file:   file,
		size:   info.Size(),
		sha256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func installCommand(size int64, checksum string, taskID ...string) string {
	// taskID is intentionally not interpolated into the remote shell. Backup
	// names use a prefix of the local binary checksum (hex-only) so no
	// operator-supplied token reaches session.Run.
	_ = taskID
	if size < 0 {
		size = 0
	}
	sizeValue := strconv.FormatInt(size, 10)
	checksum = sanitizeInstallChecksum(checksum)
	backupID := checksum
	if len(backupID) > 16 {
		backupID = backupID[:16]
	}
	return strings.Join([]string{
		"set -eu",
		"target=" + defaultInstallTarget,
		"tmp=$(mktemp /tmp/cheesewaf-install.XXXXXX)",
		"backup=\"\"",
		"restore() { status=$?; if [ \"$status\" -ne 0 ] && [ -n \"$backup\" ] && [ -f \"$backup\" ]; then cp -p \"$backup\" \"$target\" >/dev/null 2>&1 || true; fi; rm -f \"$tmp\"; exit \"$status\"; }",
		"trap restore EXIT",
		"cat > \"$tmp\"",
		"actual_size=$(wc -c < \"$tmp\" | tr -d '[:space:]')",
		"if [ \"$actual_size\" != \"" + sizeValue + "\" ]; then echo uploaded size mismatch >&2; exit 1; fi",
		"actual_sha=$(sha256sum \"$tmp\" | awk '{print $1}')",
		"if [ \"$actual_sha\" != \"" + checksum + "\" ]; then echo uploaded checksum mismatch >&2; exit 1; fi",
		"chmod 0755 \"$tmp\"",
		"\"$tmp\" --version",
		"if [ -f \"$target\" ]; then backup=\"${target}.bak." + backupID + "\"; test ! -e \"$backup\"; cp -p \"$target\" \"$backup\"; fi",
		"install -m 0755 \"$tmp\" \"$target\"",
		"\"$target\" --version",
		"rm -f \"$tmp\"",
		"trap - EXIT",
		"echo CheeseWAF installed to \"$target\"",
		"if [ -n \"$backup\" ]; then echo Previous binary backup: \"$backup\"; fi",
	}, "; ")
}

func safeTaskID(value string) bool {
	return sanitizeTaskIDToken(value) != ""
}

// sanitizeTaskIDToken rebuilds an alphanumeric/dash token so shell interpolation
// cannot carry untrusted characters into remote install scripts.
func sanitizeTaskIDToken(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 8 || len(value) > 80 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteRune(ch)
			continue
		}
		return ""
	}
	return b.String()
}

func sanitizeInstallChecksum(checksum string) string {
	checksum = strings.ToLower(strings.TrimSpace(checksum))
	if len(checksum) != 64 {
		return strings.Repeat("0", 64)
	}
	var b strings.Builder
	b.Grow(64)
	for _, ch := range checksum {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			b.WriteRune(ch)
			continue
		}
		return strings.Repeat("0", 64)
	}
	return b.String()
}

// trustedRemoteShell only accepts allowlisted fixed commands or exact install
// scripts regenerated from a parsed size+checksum. Free-form operator shell is rejected.
func trustedRemoteShell(command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("remote command is required")
	}
	// Deploy scripts are small; reject oversized payloads early (DoS / memory).
	if len(command) > 16<<10 {
		return "", fmt.Errorf("remote command too large")
	}
	// Return canonical constants so session.Run does not keep a free-form string.
	switch command {
	case remoteCheckCommand():
		return remoteCheckCommand(), nil
	case rollbackInstallCommand():
		return rollbackInstallCommand(), nil
	case "systemctl restart cheesewaf":
		return "systemctl restart cheesewaf", nil
	case "systemctl start cheesewaf":
		return "systemctl start cheesewaf", nil
	}
	size, checksum, ok := parseInstallScriptParams(command)
	if !ok {
		return "", fmt.Errorf("refusing untrusted remote shell command")
	}
	// Rebuild from sanitized numeric size + hex checksum only.
	return installCommand(size, checksum), nil
}

// parseInstallScriptParams extracts size and sha256 from an install script produced
// by installCommand. Any deviation fails closed.
func parseInstallScriptParams(command string) (int64, string, bool) {
	const sizeMarker = `if [ "$actual_size" != "`
	const shaMarker = `if [ "$actual_sha" != "`
	sizeIdx := strings.Index(command, sizeMarker)
	shaIdx := strings.Index(command, shaMarker)
	if sizeIdx < 0 || shaIdx < 0 {
		return 0, "", false
	}
	sizeRest := command[sizeIdx+len(sizeMarker):]
	sizeEnd := strings.Index(sizeRest, `"`)
	if sizeEnd <= 0 {
		return 0, "", false
	}
	sizeValue := sizeRest[:sizeEnd]
	for _, ch := range sizeValue {
		if ch < '0' || ch > '9' {
			return 0, "", false
		}
	}
	size, err := strconv.ParseInt(sizeValue, 10, 64)
	if err != nil || size < 0 {
		return 0, "", false
	}
	shaRest := command[shaIdx+len(shaMarker):]
	shaEnd := strings.Index(shaRest, `"`)
	if shaEnd != 64 {
		return 0, "", false
	}
	checksum := sanitizeInstallChecksum(shaRest[:shaEnd])
	if checksum != shaRest[:shaEnd] {
		return 0, "", false
	}
	// Exact match against regenerated script (no extra metacharacters).
	if installCommand(size, checksum) != command {
		return 0, "", false
	}
	return size, checksum, true
}

func rollbackInstallCommand() string {
	return strings.Join([]string{
		"set -eu",
		"target=" + defaultInstallTarget,
		"latest=\"\"",
		"for candidate in \"$target\".bak.*; do [ -f \"$candidate\" ] || continue; latest=\"$candidate\"; done",
		"if [ -z \"$latest\" ]; then echo no CheeseWAF binary backup found >&2; exit 1; fi",
		"\"$latest\" --version",
		"current_backup=\"\"",
		"if [ -f \"$target\" ]; then current_backup=\"${target}.pre-rollback.$(date -u +%Y%m%d%H%M%S)\"; cp -p \"$target\" \"$current_backup\"; fi",
		"install -m 0755 \"$latest\" \"$target\"",
		"\"$target\" --version",
		"echo CheeseWAF restored from \"$latest\"",
		"if [ -n \"$current_backup\" ]; then echo Previous current binary backup: \"$current_backup\"; fi",
	}, "; ")
}

func compensationCommandForAction(action string) string {
	switch strings.TrimSpace(action) {
	case compensationStartService:
		return "systemctl start cheesewaf"
	default:
		return ""
	}
}

func looksLikePrivateKey(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		strings.HasPrefix(value, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.HasPrefix(value, "-----BEGIN EC PRIVATE KEY-----") ||
		strings.HasPrefix(value, "-----BEGIN PRIVATE KEY-----")
}

func normalizeHostKeyFingerprint(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "SHA256:")
	if value == "" {
		return ""
	}
	return "SHA256:" + value
}

func validateLocalIdentityFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("identity_file contains unsupported characters")
	}
	if !strings.HasPrefix(filepath.Base(path), "cheesewaf-ssh-key-") || !strings.HasSuffix(filepath.Base(path), ".pem") {
		return fmt.Errorf("identity_file must be created by the temporary private key flow")
	}
	clean := filepath.Clean(path)
	if clean != path {
		return fmt.Errorf("identity_file must be a clean local path")
	}
	tempDir := filepath.Clean(os.TempDir())
	if filepath.Clean(filepath.Dir(path)) != tempDir {
		return fmt.Errorf("identity_file must be in the system temporary directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat identity_file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("identity_file must not be a symlink")
	}
	if info.IsDir() {
		return fmt.Errorf("identity_file must be a file")
	}
	return nil
}

func redactedSSHArgs(args []string) []string {
	out := append([]string(nil), args...)
	for idx := 0; idx < len(out)-1; idx++ {
		if out[idx] == "-i" {
			out[idx+1] = "<temporary-private-key>"
		}
	}
	return out
}

func outputStatusMessage(output string, truncated bool) string {
	output = strings.TrimSpace(output)
	if output == "" {
		if truncated {
			return "SSH command completed; output was truncated by the safety limit"
		}
		return "SSH command completed"
	}
	if truncated {
		return output + "\n(output truncated by safety limit)"
	}
	return output
}

func sanitizeSSHError(err error, req SSHDeploymentRequest) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", sanitizeTaskText(err.Error(), req))
}

func sanitizeCredentialText(value string, req SSHDeploymentRequest) string {
	for _, secret := range []string{req.Password, req.PrivateKey} {
		secret = strings.TrimSpace(secret)
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "<redacted>")
		}
	}
	return value
}

type limitWriter struct {
	w         *bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w == nil || w.w == nil || w.limit <= 0 {
		return len(p), nil
	}
	remaining := w.limit - w.w.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = w.w.Write(p[:remaining])
			w.truncated = true
		} else {
			_, _ = w.w.Write(p)
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return len(p), nil
}

func (w *limitWriter) Truncated() bool {
	return w != nil && w.truncated
}

func (r *SSHRunner) StoredCredentialCount() int {
	if r == nil {
		return 0
	}
	return len(r.storedCredentials)
}

func (r *SSHRunner) record(action string, req SSHDeploymentRequest, fields map[string]string) {
	if r == nil || r.audit == nil {
		return
	}
	safeFields := map[string]string{
		"host": strings.TrimSpace(req.Host),
		"user": strings.TrimSpace(req.User),
		"port": strconv.Itoa(normalizedSSHPort(req.Port)),
	}
	for key, value := range fields {
		safeFields[key] = value
	}
	r.audit.Record(action, safeFields)
}

func normalizedSSHPort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}
