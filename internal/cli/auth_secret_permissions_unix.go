//go:build !windows

package cli

import (
	"fmt"
	"os"
)

func protectAuthSecretFile(path string) error {
	return os.Chmod(path, 0o600)
}

func validateAuthSecretFilePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("auth secret must have mode 0600, got %o", info.Mode().Perm())
	}
	return nil
}
