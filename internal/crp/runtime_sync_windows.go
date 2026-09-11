//go:build windows

package crp

// syncRuntimeDirectory is a platform seam. The Windows implementation keeps
// the state transition functional; a future native adapter can use
// FlushFileBuffers on a directory handle where the filesystem supports it.
func syncRuntimeDirectory(string) error { return nil }
