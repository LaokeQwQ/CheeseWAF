//go:build !windows

package ai

import "os"

func replaceFileAtomic(source, target string) error {
	return os.Rename(source, target)
}

func protectApprovalFile(path string) error {
	return os.Chmod(path, 0o600)
}
