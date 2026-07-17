//go:build windows

package winctl

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureDetached(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	return nil
}
