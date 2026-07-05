package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	defaultACMESHPath = "acme.sh"
	defaultServer     = "letsencrypt"
	defaultKeyType    = "ec-256"
)

var (
	dnsAPIPattern           = regexp.MustCompile(`^dns_[a-z0-9_]+$`)
	envKeyPattern           = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	sensitiveOutputPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|API[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*\s*=\s*)[^\s'"]+`),
		regexp.MustCompile(`(?i)((?:authorization|x-api-key|api-key)\s*[:=]\s*(?:bearer\s+)?)\S+`),
	}
)

type CommandRunner interface {
	Run(ctx context.Context, env []string, name string, args ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	return combined.String(), err
}

type IssuerOptions struct {
	Config *config.Config
	Runner CommandRunner
	Now    func() time.Time
}

type ACMESHIssuer struct {
	cfg    *config.Config
	runner CommandRunner
	now    func() time.Time
}

func NewIssuer(opts IssuerOptions) *ACMESHIssuer {
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ACMESHIssuer{cfg: opts.Config, runner: runner, now: now}
}

func (i *ACMESHIssuer) Providers() []DNSProvider {
	if i == nil || i.cfg == nil {
		return nil
	}
	providers := make([]DNSProvider, 0, len(i.cfg.ACME.DNSProviders))
	for _, provider := range i.cfg.ACME.DNSProviders {
		if !provider.Enabled {
			continue
		}
		env := make(map[string]string, len(provider.Env))
		for key, value := range provider.Env {
			if value == "" {
				continue
			}
			env[key] = maskSecret(value)
		}
		providers = append(providers, DNSProvider{
			ID:      provider.ID,
			Name:    provider.Name,
			API:     provider.API,
			Env:     env,
			Enabled: provider.Enabled,
		})
	}
	return providers
}

func (i *ACMESHIssuer) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	start := i.now()
	req = i.withDefaults(req)
	result := IssueResult{
		RunID:       newRunID(),
		SiteID:      req.SiteID,
		Domains:     append([]string(nil), req.Domains...),
		KeyType:     req.KeyType,
		Server:      req.Server,
		DNSAPI:      req.DNSAPI,
		AutoRenew:   req.AutoRenew,
		Notify:      req.Notify,
		ProviderID:  req.ProviderID,
		PrimaryName: firstDomain(req.Domains),
	}
	record := func(step string, status StepStatus, message, output string) {
		result.Events = append(result.Events, Event{
			Step:      step,
			Status:    status,
			Message:   message,
			Output:    truncateOutput(output),
			Timestamp: i.now(),
		})
	}
	fail := func(step, message string, err error, output string) (IssueResult, error) {
		record(step, StepFailed, message, output)
		result.ElapsedMS = int64(i.now().Sub(start) / time.Millisecond)
		if err == nil {
			err = fmt.Errorf("%s", message)
		}
		return result, err
	}

	if err := validateIssueRequest(req); err != nil {
		return fail("validate", err.Error(), err, "")
	}
	record("validate", StepSucceeded, "request validated", "")
	if err := os.MkdirAll(req.Home, 0o700); err != nil {
		return fail("prepare_home", "failed to create acme.sh home", err, "")
	}
	if err := os.MkdirAll(req.CertDir, 0o750); err != nil {
		return fail("prepare_cert_dir", "failed to create certificate directory", err, "")
	}
	record("prepare", StepSucceeded, "acme.sh home and certificate directory ready", "")

	env := envList(req.DNSEnv)
	if req.AccountEmail != "" {
		args := []string{"--register-account", "-m", req.AccountEmail, "--server", req.Server, "--home", req.Home}
		record("account", StepRunning, "registering or refreshing ACME account", "")
		output, err := i.runner.Run(ctx, env, req.ACMESHPath, args...)
		if err != nil {
			return fail("account", "acme.sh account registration failed", err, output)
		}
		record("account", StepSucceeded, "ACME account is ready", output)
	}

	issueArgs := []string{"--issue", "--dns", req.DNSAPI, "--server", req.Server, "--keylength", req.KeyType, "--home", req.Home}
	for _, domain := range req.Domains {
		issueArgs = append(issueArgs, "-d", domain)
	}
	record("dns_create", StepRunning, "acme.sh DNS API will create DNS-01 TXT records", "")
	record("issue", StepRunning, "issuing certificate with acme.sh", "")
	output, err := i.runner.Run(ctx, env, req.ACMESHPath, issueArgs...)
	if err != nil {
		record("dns_cleanup", StepSucceeded, "acme.sh DNS API handles DNS-01 cleanup; no certificate removal command was executed", "")
		return fail("issue", "acme.sh issue command failed", err, output)
	}
	record("issue", StepSucceeded, "certificate issued", output)

	result.CertFile = filepath.Join(req.CertDir, "fullchain.cer")
	result.Fullchain = result.CertFile
	result.KeyFile = filepath.Join(req.CertDir, "site.key")
	installArgs := []string{
		"--install-cert",
		"-d", req.Domains[0],
		"--key-file", result.KeyFile,
		"--fullchain-file", result.CertFile,
		"--home", req.Home,
	}
	if req.ReloadCmd != "" {
		installArgs = append(installArgs, "--reloadcmd", req.ReloadCmd)
	}
	record("deploy", StepRunning, "installing certificate files", "")
	output, err = i.runner.Run(ctx, env, req.ACMESHPath, installArgs...)
	if err != nil {
		return fail("deploy", "acme.sh install-cert command failed", err, output)
	}
	record("deploy", StepSucceeded, "certificate files installed", output)
	record("dns_cleanup", StepSucceeded, "acme.sh DNS API completed DNS-01 cleanup", "")

	result.IssuedAt = i.now()
	result.RenewAfter = result.IssuedAt.Add(60 * 24 * time.Hour)
	result.ElapsedMS = int64(i.now().Sub(start) / time.Millisecond)
	return result, nil
}

func (i *ACMESHIssuer) withDefaults(req IssueRequest) IssueRequest {
	if req.ACMESHPath == "" {
		req.ACMESHPath = defaultACMESHPath
	}
	if req.Server == "" {
		req.Server = defaultServer
	}
	if req.KeyType == "" {
		req.KeyType = defaultKeyType
	}
	if i != nil && i.cfg != nil {
		acmeCfg := i.cfg.ACME
		if req.ACMESHPath == defaultACMESHPath && acmeCfg.ACMESHPath != "" {
			req.ACMESHPath = acmeCfg.ACMESHPath
		}
		if req.Server == defaultServer && acmeCfg.Server != "" {
			req.Server = acmeCfg.Server
		}
		if req.KeyType == defaultKeyType && acmeCfg.KeyType != "" {
			req.KeyType = acmeCfg.KeyType
		}
		if req.AccountEmail == "" {
			req.AccountEmail = acmeCfg.AccountEmail
		}
		if req.Home == "" {
			req.Home = acmeCfg.Home
		}
		if req.CertDir == "" {
			req.CertDir = acmeCfg.CertDir
		}
		if req.ReloadCmd == "" {
			req.ReloadCmd = acmeCfg.ReloadCommand
		}
		if !req.Notify {
			req.Notify = acmeCfg.Notify
		}
		if req.ProviderID != "" {
			for _, provider := range acmeCfg.DNSProviders {
				if provider.ID == req.ProviderID {
					if req.DNSAPI == "" {
						req.DNSAPI = provider.API
					}
					if len(req.DNSEnv) == 0 {
						req.DNSEnv = provider.Env
					}
					break
				}
			}
		}
		baseDir := i.cfg.Setup.DataDir
		if req.Home == "" && baseDir != "" {
			req.Home = filepath.Join(baseDir, "acme")
		}
		if req.CertDir == "" && baseDir != "" {
			req.CertDir = filepath.Join(baseDir, "certs", safePathSegment(firstDomain(req.Domains)))
		}
	}
	if req.Home == "" {
		req.Home = filepath.Join(".", "data", "acme")
	}
	if req.CertDir == "" {
		req.CertDir = filepath.Join(".", "data", "certs", safePathSegment(firstDomain(req.Domains)))
	}
	req.Domains = normalizeDomains(req.Domains)
	if req.DNSEnv == nil {
		req.DNSEnv = map[string]string{}
	}
	return req
}

func validateIssueRequest(req IssueRequest) error {
	if len(req.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	for _, domain := range req.Domains {
		if !validDomain(domain) {
			return fmt.Errorf("invalid domain %q", domain)
		}
	}
	if !dnsAPIPattern.MatchString(req.DNSAPI) {
		return fmt.Errorf("dns_api must look like dns_cf or dns_ali")
	}
	switch strings.ToLower(strings.TrimSpace(req.KeyType)) {
	case "ec-256", "ec-384", "2048", "3072", "4096":
	default:
		return fmt.Errorf("unsupported key_type %q", req.KeyType)
	}
	if strings.TrimSpace(req.ACMESHPath) == "" {
		return fmt.Errorf("acme_sh_path is required")
	}
	if strings.TrimSpace(req.Home) == "" {
		return fmt.Errorf("home is required")
	}
	if strings.TrimSpace(req.CertDir) == "" {
		return fmt.Errorf("cert_dir is required")
	}
	for key := range req.DNSEnv {
		if !envKeyPattern.MatchString(key) {
			return fmt.Errorf("invalid DNS env var %q", key)
		}
	}
	return nil
}

func envList(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func normalizeDomains(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func validDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" || len(domain) > 253 {
		return false
	}
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}
	if strings.ContainsAny(domain, "/:@\\") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func firstDomain(values []string) string {
	domains := normalizeDomains(values)
	if len(domains) == 0 {
		return "site"
	}
	return domains[0]
}

func safePathSegment(value string) string {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "*.")
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('-')
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "site"
	}
	return out
}

func maskSecret(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 6 {
		return "******"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

func truncateOutput(value string) string {
	value = strings.TrimSpace(redactSensitiveOutput(value))
	const max = 4096
	if len(value) <= max {
		return value
	}
	return value[:max] + "...(truncated)"
}

func redactSensitiveOutput(value string) string {
	out := value
	for _, pattern := range sensitiveOutputPatterns {
		out = pattern.ReplaceAllString(out, "${1}******")
	}
	return out
}

func newRunID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("acme-%d", time.Now().UnixNano())
	}
	return "acme-" + hex.EncodeToString(buf)
}
