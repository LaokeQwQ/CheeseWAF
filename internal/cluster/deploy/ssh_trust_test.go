package deploy

import (
	"strings"
	"testing"
)

func TestTrustedRemoteShellAllowlist(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	for _, cmd := range []string{
		remoteCheckCommand(),
		rollbackInstallCommand(),
		"systemctl restart cheesewaf",
		"systemctl start cheesewaf",
		installCommand(12, sum),
	} {
		got, err := trustedRemoteShell(cmd)
		if err != nil {
			t.Fatalf("trustedRemoteShell err=%v for %q", err, truncate(cmd, 48))
		}
		if got == "" {
			t.Fatal("empty trusted command")
		}
	}
}

func TestTrustedRemoteShellRejectsInjection(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	base := installCommand(12, sum)
	for _, bad := range []string{
		"",
		"rm -rf /",
		base + "; curl evil.test",
		"set -eu; target=/usr/local/bin/cheesewaf; evil",
		"systemctl restart cheesewaf; id",
	} {
		if _, err := trustedRemoteShell(bad); err == nil {
			t.Fatalf("trustedRemoteShell accepted %q", truncate(bad, 64))
		}
	}
}

func TestInstallCommandIgnoresTaskIDInShell(t *testing.T) {
	sum := strings.Repeat("cd", 32)
	a := installCommand(99, sum, "task-id-with-metachar;id")
	b := installCommand(99, sum)
	if a != b {
		t.Fatal("installCommand must not embed operator task IDs into the shell script")
	}
	if strings.Contains(a, "task-id") || strings.Contains(a, "metachar") {
		t.Fatal("task id leaked into install script")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
