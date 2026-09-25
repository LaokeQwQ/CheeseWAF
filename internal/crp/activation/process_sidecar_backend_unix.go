//go:build !windows

package activation

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureProcessSidecarCommand(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func killProcessSidecarCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func validateProcessExecutableMode(mode os.FileMode) error {
	if mode.Perm()&0o111 == 0 {
		return errors.New("executable has no execute bit")
	}
	return nil
}

func validateProcessPathSecuritySupported() error { return nil }
