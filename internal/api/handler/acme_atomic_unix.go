//go:build !windows

package handler

import "os"

func replaceACMEFileAtomic(source, target string) error {
	return os.Rename(source, target)
}
