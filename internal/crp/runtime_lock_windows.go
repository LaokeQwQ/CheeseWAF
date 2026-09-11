//go:build windows

package crp

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func runtimeLockSupported() bool { return true }

func lockRuntimeFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
}

func unlockRuntimeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}

func runtimeLeaseBusy(err error) bool {
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
