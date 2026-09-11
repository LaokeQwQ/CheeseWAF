//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package nativeraft

import (
	"fmt"
	"os"
	"syscall"
)

func checkOwned(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect owner for %q: unsupported stat data", path)
	}
	uid := uint32(os.Geteuid())
	if uint32(stat.Uid) != uid {
		return fmt.Errorf("path %q is not owned by the running user", path)
	}
	return nil
}

func checkOwnedOrRoot(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect owner for %q: unsupported stat data", path)
	}
	uid := uint32(os.Geteuid())
	if uint32(stat.Uid) != uid && uint32(stat.Uid) != 0 {
		return fmt.Errorf("path %q is not owned by the running user or root", path)
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
