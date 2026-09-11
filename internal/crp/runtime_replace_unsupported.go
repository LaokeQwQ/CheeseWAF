//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows)

package crp

import "os"

func replaceRuntimeFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
