//go:build windows

package activation

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureProcessSidecarCommand(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	return nil
}

func killProcessSidecarCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func validateProcessExecutableMode(os.FileMode) error { return nil }

func validateProcessPathSecuritySupported() error {
	return errors.New("secure executable ACL and reparse-point validation is unsupported on windows")
}
