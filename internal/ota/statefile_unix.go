//go:build !windows

package ota

import (
	"fmt"
	"os"
)

func protectStateFile(path string) error {
	return os.Chmod(path, 0o600)
}

func replaceStateFileAtomic(source, target string) error {
	return os.Rename(source, target)
}

func validateStateFilePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("state file must have mode 0600, got %o", info.Mode().Perm())
	}
	return nil
}
