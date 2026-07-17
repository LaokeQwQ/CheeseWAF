//go:build !windows

package winctl

import (
	"os/exec"
	"syscall"
)

func configureDetached(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	return nil
}
