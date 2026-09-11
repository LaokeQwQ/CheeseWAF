//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package crp

import (
	"errors"
	"os"
	"syscall"
)

func runtimeLockSupported() bool { return true }

func lockRuntimeFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockRuntimeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

func runtimeLeaseBusy(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
