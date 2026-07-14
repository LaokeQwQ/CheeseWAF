//go:build linux

package assets

import "golang.org/x/sys/unix"

func openSecureRootAt(dirfd int, name string) (int, error) {
	return unix.Openat2(dirfd, name, secureRootOpenHow())
}

func secureRootOpenHow() *unix.OpenHow {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	return how
}
