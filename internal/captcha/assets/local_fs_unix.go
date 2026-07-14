//go:build linux || darwin

package assets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type localAssetFS struct {
	mu       sync.Mutex
	root     *os.File
	closeErr error
}

func openLocalAssetFS(path string) (*localAssetFS, error) {
	fd, err := openSecureRoot(path)
	if err != nil {
		return nil, rejectLinkError(path, err)
	}
	if err = unix.Fchmod(fd, 0o700); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &localAssetFS{root: os.NewFile(uintptr(fd), path)}, nil
}

func openSecureRoot(path string) (int, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return -1, err
	}
	clean := filepath.Clean(abs)
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	relative := strings.TrimPrefix(clean, string(filepath.Separator))
	if relative == "" {
		return fd, nil
	}
	for _, name := range strings.Split(relative, string(filepath.Separator)) {
		next, openErr := openSecureRootAt(fd, name)
		if errors.Is(openErr, unix.ENOENT) {
			mkdirErr := unix.Mkdirat(fd, name, 0o700)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				unix.Close(fd)
				return -1, mkdirErr
			}
			next, openErr = openSecureRootAt(fd, name)
		}
		if openErr != nil {
			unix.Close(fd)
			return -1, openErr
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func (f *localAssetFS) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.root == nil {
		return f.closeErr
	}
	f.closeErr = f.root.Close()
	f.root = nil
	return f.closeErr
}

func (f *localAssetFS) rootFD() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.root == nil {
		return -1, os.ErrClosed
	}
	fd, err := unix.Dup(int(f.root.Fd()))
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}
func (f *localAssetFS) kindFD(kind Kind, create bool) (int, error) {
	name := string(kind)
	rootfd, err := f.rootFD()
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootfd)
	fd, err := unix.Openat(rootfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(rootfd, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
		fd, err = unix.Openat(rootfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return -1, rejectLinkError(name, err)
	}
	if err = unix.Fchmod(fd, 0o700); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (f *localAssetFS) ensureKind(kind Kind) error {
	fd, err := f.kindFD(kind, true)
	if err == nil {
		err = unix.Close(fd)
	}
	return err
}

func (f *localAssetFS) open(kind Kind, name string) (*os.File, error) {
	dirfd, err := f.kindFD(kind, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, rejectLinkError(name, err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("captcha asset %q is not a regular file", name)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (f *localAssetFS) readFile(kind Kind, name string, limit int64) ([]byte, error) {
	r, err := f.open(kind, name)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, limit))
}

func (f *localAssetFS) readDir(kind Kind) ([]os.DirEntry, error) {
	fd, err := f.kindFD(kind, false)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(fd), string(kind))
	defer d.Close()
	return d.ReadDir(-1)
}

func (f *localAssetFS) atomicWrite(kind Kind, name string, data []byte, mode os.FileMode) (retErr error) {
	dirfd, err := f.kindFD(kind, false)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	tmp := ".asset-" + name
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if errors.Is(err, unix.EEXIST) {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		fd, err = unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	}
	if err != nil {
		return rejectLinkError(tmp, err)
	}
	file := os.NewFile(uintptr(fd), tmp)
	closed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, file.Close())
		}
		if retErr != nil {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	_, writeErr := io.Copy(file, bytes.NewReader(data))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	closed = true
	writeErr = errors.Join(writeErr, closeErr)
	if writeErr != nil {
		return writeErr
	}
	if err = unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return err
	}
	return unix.Fsync(dirfd)
}

func (f *localAssetFS) remove(kind Kind, name string) error {
	dirfd, err := f.kindFD(kind, false)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	var st unix.Stat_t
	if err = unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = unix.Unlinkat(dirfd, name, 0)
		return fmt.Errorf("refusing linked captcha asset %q", name)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("captcha asset %q is not a regular file", name)
	}
	if err = unix.Unlinkat(dirfd, name, 0); err != nil {
		return err
	}
	return unix.Fsync(dirfd)
}

func rejectLinkError(name string, err error) error {
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("refusing linked captcha asset path %q: %w", name, err)
	}
	return err
}
