package deploy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SSHDeploymentRequest struct {
	Host           string `json:"host"`
	User           string `json:"user"`
	Port           int    `json:"port"`
	Password       string `json:"password,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	identityFile   string
	SaveCredential bool   `json:"save_credential"`
	Action         string `json:"action,omitempty"`
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
}

type SSHRunner struct {
	audit             AuditRecorder
	timeout           time.Duration
	outputLimit       int
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
	return &SSHRunner{audit: opts.Audit, timeout: timeout, outputLimit: outputLimit, storedCredentials: map[string]string{}}
}

func (r *SSHRunner) Prepare(_ context.Context, req SSHDeploymentRequest) error {
	prepared, cleanup, err := r.prepareRequest(context.Background(), req)
	if cleanup != nil {
		defer cleanup()
	}
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
	prepared, cleanup, err := r.prepareRequest(ctx, req)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return CheckResult{}, err
	}
	args, err := r.BuildSSHArgs(prepared)
	if err != nil {
		return CheckResult{}, err
	}
	r.record("ssh_deploy.check", prepared, nil)
	return CheckResult{
		OK:        true,
		Host:      strings.TrimSpace(prepared.Host),
		User:      strings.TrimSpace(prepared.User),
		Port:      normalizedSSHPort(prepared.Port),
		Command:   append([]string{"ssh"}, redactedSSHArgs(args)...),
		CheckedAt: time.Now().UTC(),
	}, ctx.Err()
}

func (r *SSHRunner) Deploy(ctx context.Context, req SSHDeploymentRequest) (DeployResult, error) {
	if strings.TrimSpace(req.Action) == "" || strings.TrimSpace(req.Action) == actionCheck {
		return DeployResult{}, fmt.Errorf("deploy action must be install or restart-service")
	}
	prepared, cleanup, err := r.prepareRequest(ctx, req)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return DeployResult{}, err
	}
	args, err := r.BuildSSHArgs(prepared)
	if err != nil {
		return DeployResult{}, err
	}
	started := time.Now().UTC()
	cmdCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "ssh", args...)
	var output bytes.Buffer
	limited := &limitWriter{w: &output, limit: r.outputLimit}
	cmd.Stdout = limited
	cmd.Stderr = limited
	err = cmd.Run()
	if cmdCtx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("ssh deployment timed out after %s", r.timeout)
	}
	result := DeployResult{
		OK:              err == nil,
		Host:            strings.TrimSpace(prepared.Host),
		StartedAt:       started,
		FinishedAt:      time.Now().UTC(),
		Output:          output.String(),
		OutputTruncated: limited.Truncated(),
	}
	fields := map[string]string{"ok": strconv.FormatBool(result.OK)}
	if err != nil {
		fields["error"] = err.Error()
	}
	r.record("ssh_deploy.run", prepared, fields)
	if err != nil {
		return result, err
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
	if strings.TrimSpace(req.Password) != "" {
		return nil, fmt.Errorf("ssh password authentication is not supported by the temporary runner; use SSH agent or key-based system ssh configuration")
	}
	if req.SaveCredential {
		return nil, fmt.Errorf("saving SSH credentials is not supported by the temporary runner")
	}
	if strings.TrimSpace(req.PrivateKey) != "" {
		return nil, fmt.Errorf("raw private key content must be materialized with prepareRequest before building ssh args")
	}
	identityFile := strings.TrimSpace(req.identityFile)
	if identityFile != "" {
		if err := validateLocalIdentityFile(identityFile); err != nil {
			return nil, err
		}
	}
	command, err := remoteCommandForAction(req.Action)
	if err != nil {
		return nil, err
	}
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-p", strconv.Itoa(port),
	}
	if identityFile != "" {
		args = append(args, "-i", identityFile)
	}
	args = append(args, user+"@"+host, command)
	return args, nil
}

func (r *SSHRunner) prepareRequest(_ context.Context, req SSHDeploymentRequest) (SSHDeploymentRequest, func(), error) {
	if strings.TrimSpace(req.PrivateKey) == "" {
		return req, nil, nil
	}
	key := strings.TrimSpace(req.PrivateKey)
	if !looksLikePrivateKey(key) {
		return SSHDeploymentRequest{}, nil, fmt.Errorf("private_key must be an OpenSSH or PEM private key")
	}
	tmp, err := os.CreateTemp("", "cheesewaf-ssh-key-*.pem")
	if err != nil {
		return SSHDeploymentRequest{}, nil, fmt.Errorf("create temporary ssh key: %w", err)
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return SSHDeploymentRequest{}, nil, fmt.Errorf("secure temporary ssh key: %w", err)
	}
	if _, err := tmp.WriteString(key); err != nil {
		_ = tmp.Close()
		cleanup()
		return SSHDeploymentRequest{}, nil, fmt.Errorf("write temporary ssh key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return SSHDeploymentRequest{}, nil, fmt.Errorf("close temporary ssh key: %w", err)
	}
	req.PrivateKey = ""
	req.identityFile = name
	return req, cleanup, nil
}

const (
	actionCheck          = "check"
	actionInstall        = "install"
	actionRestartService = "restart-service"
)

func remoteCommandForAction(action string) (string, error) {
	switch strings.TrimSpace(action) {
	case "", actionCheck:
		return "true", nil
	case actionInstall:
		return "cheesewaf --version", nil
	case actionRestartService:
		return "systemctl restart cheesewaf", nil
	default:
		return "", fmt.Errorf("unsupported ssh deployment action")
	}
}

func looksLikePrivateKey(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		strings.HasPrefix(value, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.HasPrefix(value, "-----BEGIN EC PRIVATE KEY-----") ||
		strings.HasPrefix(value, "-----BEGIN PRIVATE KEY-----")
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
