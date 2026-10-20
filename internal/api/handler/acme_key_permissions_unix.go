//go:build !windows

package handler

import (
	"fmt"
	"os"
)

func protectACMEPrivateKey(path string) error {
	return os.Chmod(path, 0o600)
}

func validateACMEPrivateKeyPermissions(path string, _ os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private key: %w", err)
	}
	if info == nil || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key permissions must be owner-only")
	}
	return nil
}
