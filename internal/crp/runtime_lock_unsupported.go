//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows)

package crp

import (
	"os"
)

func runtimeLockSupported() bool { return false }

func lockRuntimeFile(*os.File) error   { return ErrRuntimeLockUnavailable }
func unlockRuntimeFile(*os.File) error { return nil }
func runtimeLeaseBusy(error) bool      { return false }
