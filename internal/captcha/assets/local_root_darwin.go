//go:build darwin

package assets

import "golang.org/x/sys/unix"

func openSecureRootAt(dirfd int, name string) (int, error) {
	return unix.Openat(dirfd, name, secureRootOpenFlags(), 0)
}

func secureRootOpenFlags() int {
	return unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
}
