//go:build !windows

package setup

import (
	"fmt"
	"os"
)

func protectSetupSecretFile(path string) error {
	return os.Chmod(path, 0o600)
}

func replaceSetupSecretFile(source, target string) error {
	return os.Rename(source, target)
}

func validateSetupSecretFilePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("setup secret file is accessible by group or others: mode %o", info.Mode().Perm())
	}
	return nil
}
