//go:build !windows

package cli

import (
	"os/exec"
	"syscall"
)

func configureServiceDetached(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return nil
}
