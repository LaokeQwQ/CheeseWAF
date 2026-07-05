package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type recordedCommand struct {
	name string
	args []string
	env  []string
}

type fakeRunner struct {
	commands []recordedCommand
	failOn   string
}

func (r *fakeRunner) Run(_ context.Context, env []string, name string, args ...string) (string, error) {
	r.commands = append(r.commands, recordedCommand{
		name: name,
		args: append([]string(nil), args...),
		env:  append([]string(nil), env...),
	})
	if r.failOn != "" && containsArg(args, r.failOn) {
		return "simulated failure", errors.New("command failed")
	}
	return "ok", nil
}

func TestIssuerRunsACMESHPipeline(t *testing.T) {
	runner := &fakeRunner{}
	issuer := NewIssuer(IssuerOptions{
		Config: &config.Config{Setup: config.SetupConfig{DataDir: t.TempDir()}},
		Runner: runner,
		Now:    fixedClock(),
	})

	result, err := issuer.Issue(context.Background(), IssueRequest{
		SiteID:       "site-a",
		Domains:      []string{"Example.COM", "www.example.com"},
		DNSAPI:       "dns_cf",
		DNSEnv:       map[string]string{"CF_Token": "bad"},
		AccountEmail: "ops@example.com",
		Server:       "zerossl",
		KeyType:      "ec-384",
		ACMESHPath:   "/usr/local/bin/acme.sh",
		Home:         t.TempDir(),
		CertDir:      t.TempDir(),
		ReloadCmd:    "systemctl reload cheesewaf",
		AutoRenew:    true,
		Notify:       true,
	})
	if err == nil {
		t.Fatal("expected invalid DNS env key to fail before command execution")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid input should not run commands: %+v", runner.commands)
	}

	result, err = issuer.Issue(context.Background(), IssueRequest{
		SiteID:       "site-a",
		Domains:      []string{"Example.COM", "www.example.com"},
		DNSAPI:       "dns_cf",
		DNSEnv:       map[string]string{"CF_TOKEN": "secret-token"},
		AccountEmail: "ops@example.com",
		Server:       "zerossl",
		KeyType:      "ec-384",
		ACMESHPath:   "/usr/local/bin/acme.sh",
		Home:         t.TempDir(),
		CertDir:      t.TempDir(),
		ReloadCmd:    "systemctl reload cheesewaf",
		AutoRenew:    true,
		Notify:       true,
	})
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("expected account, issue, install commands, got %d: %+v", len(runner.commands), runner.commands)
	}
	assertArgs(t, runner.commands[0].args, "--register-account", "-m", "ops@example.com", "--server", "zerossl")
	assertArgs(t, runner.commands[1].args, "--issue", "--dns", "dns_cf", "--server", "zerossl", "--keylength", "ec-384", "-d", "example.com", "-d", "www.example.com")
	assertArgs(t, runner.commands[2].args, "--install-cert", "-d", "example.com", "--key-file", result.KeyFile, "--fullchain-file", result.Fullchain, "--reloadcmd", "systemctl reload cheesewaf")
	if !containsString(runner.commands[1].env, "CF_TOKEN=secret-token") {
		t.Fatalf("dns env was not passed to acme.sh: %+v", runner.commands[1].env)
	}
	if result.CertFile == "" || result.KeyFile == "" || result.Fullchain == "" {
		t.Fatalf("expected installed certificate paths: %+v", result)
	}
	if result.RenewAfter.IsZero() || result.ElapsedMS < 0 || result.RunID == "" {
		t.Fatalf("expected runtime metadata: %+v", result)
	}
	if !hasEvent(result.Events, "dns_cleanup", StepSucceeded) {
		t.Fatalf("expected dns cleanup event: %+v", result.Events)
	}
}

func TestIssuerFailureKeepsEventsAndDoesNotRemoveCertificate(t *testing.T) {
	runner := &fakeRunner{failOn: "--issue"}
	issuer := NewIssuer(IssuerOptions{Config: &config.Config{Setup: config.SetupConfig{DataDir: t.TempDir()}}, Runner: runner, Now: fixedClock()})

	result, err := issuer.Issue(context.Background(), IssueRequest{
		SiteID:     "site-a",
		Domains:    []string{"example.com"},
		DNSAPI:     "dns_ali",
		DNSEnv:     map[string]string{"Ali_Key": "bad"},
		ACMESHPath: "acme.sh",
		Home:       t.TempDir(),
		CertDir:    t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid DNS env var") {
		t.Fatalf("expected invalid env error, got %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid request should not execute acme.sh: %+v", runner.commands)
	}

	result, err = issuer.Issue(context.Background(), IssueRequest{
		SiteID:     "site-a",
		Domains:    []string{"example.com"},
		DNSAPI:     "dns_ali",
		DNSEnv:     map[string]string{"ALI_KEY": "key", "ALI_SECRET": "secret"},
		ACMESHPath: "acme.sh",
		Home:       t.TempDir(),
		CertDir:    t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected issue command failure")
	}
	if !hasEvent(result.Events, "issue", StepFailed) {
		t.Fatalf("expected failed issue event: %+v", result.Events)
	}
	if !hasEvent(result.Events, "dns_cleanup", StepSucceeded) {
		t.Fatalf("expected cleanup note event: %+v", result.Events)
	}
	for _, command := range runner.commands {
		if containsArg(command.args, "--remove") {
			t.Fatalf("issuer must not remove certificates/domains on issue failure: %+v", runner.commands)
		}
	}
}

func TestIssuerRejectsUnsafeACMEServerBeforeCommandExecution(t *testing.T) {
	for _, server := range []string{
		"http://acme.example.com/directory",
		"https://127.0.0.1/acme/directory",
		"https://user:pass@acme.example.com/directory",
	} {
		runner := &fakeRunner{}
		issuer := NewIssuer(IssuerOptions{
			Config: &config.Config{Setup: config.SetupConfig{DataDir: t.TempDir()}},
			Runner: runner,
			Now:    fixedClock(),
		})

		_, err := issuer.Issue(context.Background(), IssueRequest{
			SiteID:     "site-a",
			Domains:    []string{"example.com"},
			DNSAPI:     "dns_cf",
			DNSEnv:     map[string]string{"CF_TOKEN": "secret"},
			Server:     server,
			ACMESHPath: "acme.sh",
			Home:       t.TempDir(),
			CertDir:    t.TempDir(),
		})
		if err == nil || !strings.Contains(err.Error(), "server is invalid") {
			t.Fatalf("expected unsafe ACME server %q to fail validation, got %v", server, err)
		}
		if len(runner.commands) != 0 {
			t.Fatalf("unsafe ACME server should not execute commands: %+v", runner.commands)
		}
	}
}

func TestIssuerProvidersMaskSecrets(t *testing.T) {
	issuer := NewIssuer(IssuerOptions{Config: &config.Config{ACME: config.ACMEConfig{
		DNSProviders: []config.ACMEDNSProviderConfig{
			{ID: "cf", Name: "Cloudflare", API: "dns_cf", Enabled: true, Env: map[string]string{"CF_TOKEN": "abcdef123456"}},
			{ID: "disabled", Name: "Disabled", API: "dns_dp", Enabled: false, Env: map[string]string{"DP_KEY": "secret"}},
		},
	}}})
	providers := issuer.Providers()
	if len(providers) != 1 {
		t.Fatalf("expected one enabled provider, got %+v", providers)
	}
	if got := providers[0].Env["CF_TOKEN"]; got != "ab****56" {
		t.Fatalf("expected masked secret, got %q", got)
	}
}

func assertArgs(t *testing.T, got []string, expected ...string) {
	t.Helper()
	cursor := 0
	for _, want := range expected {
		found := false
		for cursor < len(got) {
			if got[cursor] == want {
				found = true
				cursor++
				break
			}
			cursor++
		}
		if !found {
			t.Fatalf("expected args to contain ordered %q in %+v", want, got)
		}
	}
}

func hasEvent(events []Event, step string, status StepStatus) bool {
	for _, event := range events {
		if event.Step == step && event.Status == status {
			return true
		}
	}
	return false
}

func containsArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func fixedClock() func() time.Time {
	current := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		current = current.Add(10 * time.Millisecond)
		return current
	}
}
