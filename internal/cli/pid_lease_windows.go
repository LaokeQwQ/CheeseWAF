//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockPIDLeaseFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, nil)
}

func unlockPIDLeaseFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, nil)
}
