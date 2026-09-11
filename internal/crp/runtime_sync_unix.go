//go:build !windows

package crp

import "os"

// syncRuntimeDirectory makes a completed rename durable on Unix-like hosts.
// Windows uses its own filesystem semantics and is handled by the platform
// stub in runtime_sync_windows.go.
func syncRuntimeDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
