//go:build darwin

package assets

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func normalizeSecureRootPath(path string) string {
	for _, alias := range []string{"var", "tmp", "etc"} {
		prefix := string(filepath.Separator) + alias
		target := string(filepath.Separator) + "private" + prefix
		if path == prefix {
			return target
		}
		if strings.HasPrefix(path, prefix+string(filepath.Separator)) {
			return target + strings.TrimPrefix(path, prefix)
		}
	}
	return path
}

func openSecureRootAt(dirfd int, name string) (int, error) {
	return unix.Openat(dirfd, name, secureRootOpenFlags(), 0)
}

func secureRootOpenFlags() int {
	return unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
}
