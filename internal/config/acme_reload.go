package config

import (
	"fmt"
	"strings"
)

const (
	ACMEReloadProfileDisabled       = "disabled"
	ACMEReloadProfileSystemdRestart = "systemd-restart"
	ACMEReloadSystemdRestartCommand = "/usr/bin/systemctl restart cheesewaf.service"
)

func ResolveACMEReloadCommand(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	switch value {
	case ACMEReloadProfileDisabled:
		return "", nil
	case ACMEReloadProfileSystemdRestart, ACMEReloadSystemdRestartCommand:
		return ACMEReloadSystemdRestartCommand, nil
	default:
		return "", fmt.Errorf("must be empty, %q, %q, or the exact approved command %q", ACMEReloadProfileDisabled, ACMEReloadProfileSystemdRestart, ACMEReloadSystemdRestartCommand)
	}
}
