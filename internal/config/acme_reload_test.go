package config

import (
	"strings"
	"testing"
)

func TestResolveACMEReloadCommandAcceptsDocumentedProfilesAndMapping(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "disabled profile", value: ACMEReloadProfileDisabled, want: ""},
		{name: "systemd profile", value: ACMEReloadProfileSystemdRestart, want: ACMEReloadSystemdRestartCommand},
		{name: "exact systemd command", value: ACMEReloadSystemdRestartCommand, want: ACMEReloadSystemdRestartCommand},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveACMEReloadCommand(tt.value)
			if err != nil {
				t.Fatalf("ResolveACMEReloadCommand(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("ResolveACMEReloadCommand(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestResolveACMEReloadCommandRejectsShellWrappersAndBypasses(t *testing.T) {
	values := []string{
		"sh -c 'systemctl restart cheesewaf.service'",
		"/bin/sh -c /usr/bin/systemctl restart cheesewaf.service",
		"/usr/bin/env systemctl restart cheesewaf.service",
		"FOO=bar /usr/bin/systemctl restart cheesewaf.service",
		`"/usr/bin/systemctl restart cheesewaf.service"`,
		"$(/usr/bin/systemctl restart cheesewaf.service)",
		"`/usr/bin/systemctl restart cheesewaf.service`",
		"reload() { /usr/bin/systemctl restart cheesewaf.service; }; reload",
		"/usr/bin/systemctl restart cheesewaf.service; id",
		"/usr/bin/systemctl restart cheesewaf.service && id",
		"/usr/bin/systemctl restart cheesewaf.service || id",
		"/usr/bin/systemctl restart cheesewaf.service --no-block",
		"/usr/bin/systemctl restart other.service",
		"/bin/systemctl restart cheesewaf.service",
		"/tmp/reload-cheesewaf",
		"/usr/bin/systemctl reload cheesewaf",
		"systemctl restart cheesewaf.service",
		" systemd-restart",
		"systemd-restart ",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			if resolved, err := ResolveACMEReloadCommand(value); err == nil {
				t.Fatalf("expected %q to be rejected, resolved to %q", value, resolved)
			}
		})
	}
}

func TestValidateRejectsUnapprovedACMEReloadCommandEvenWhenDisabled(t *testing.T) {
	cfg := Default()
	cfg.ACME.Enabled = false
	cfg.ACME.ReloadCommand = "/bin/sh -c 'id'"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "acme.reload_command") {
		t.Fatalf("expected disabled ACME config to reject reload command, got %v", err)
	}
}
