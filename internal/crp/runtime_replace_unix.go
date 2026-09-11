//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package crp

import "os"

func replaceRuntimeFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
