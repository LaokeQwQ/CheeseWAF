package crp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// runtimeLease is an operation-scoped, non-blocking OS lease. It deliberately
// has no finalizer: relying on GC for release would make lock lifetime
// nondeterministic. Callers must close it on every path.
type runtimeLease struct {
	file   *os.File
	mu     sync.Mutex
	closed bool
}

func runtimeLockPath(root string) string {
	return filepath.Join(root, runtimeLockFileName)
}

// ensureRuntimeLockFile creates the permanent lock sentinel and rejects a
// symlink, non-regular file, or permissive mode. The sentinel must never be
// garbage-collected or replaced while a store is in use: replacing it would
// create a second inode and defeat advisory locking.
func ensureRuntimeLockFile(root string) error {
	path := runtimeLockPath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			if !errors.Is(createErr, os.ErrExist) {
				return fmt.Errorf("create runtime lock: %w", createErr)
			}
			info, err = os.Lstat(path)
		} else {
			if syncErr := f.Sync(); syncErr != nil {
				_ = f.Close()
				return fmt.Errorf("sync runtime lock: %w", syncErr)
			}
			if closeErr := f.Close(); closeErr != nil {
				return fmt.Errorf("close runtime lock: %w", closeErr)
			}
			return syncRuntimeDirectory(root)
		}
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrRuntimeSymlink
	}
	if !info.Mode().IsRegular() {
		return ErrRuntimePath
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return ErrRuntimePath
		}
		info, err = os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return ErrRuntimePath
		}
	}
	return nil
}

func acquireRuntimeLease(root string) (*runtimeLease, error) {
	if root == "" {
		return nil, ErrRuntimeConfig
	}
	if !runtimeLockSupported() {
		return nil, ErrRuntimeLockUnavailable
	}
	if err := ensureRuntimeLockFile(root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRuntimeLockUnavailable, err)
	}
	file, err := os.OpenFile(runtimeLockPath(root), os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open lease: %v", ErrRuntimeLockUnavailable, err)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: stat lease: %v", ErrRuntimeLockUnavailable, statErr)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: unsafe lease sentinel", ErrRuntimeLockUnavailable)
	}
	if err := lockRuntimeFile(file); err != nil {
		_ = file.Close()
		if runtimeLeaseBusy(err) {
			return nil, ErrRuntimeBusy
		}
		return nil, fmt.Errorf("%w: acquire lease: %v", ErrRuntimeLockUnavailable, err)
	}
	return &runtimeLease{file: file}, nil
}

func (l *runtimeLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	unlockErr := unlockRuntimeFile(l.file)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
