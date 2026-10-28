//go:build windows

package materializer

import "golang.org/x/sys/windows"

// durableRename replaces the destination and flushes the directory entry.
// MoveFileEx with MOVEFILE_WRITE_THROUGH is the Windows equivalent of the
// POSIX file-sync plus directory-sync sequence this store relies on.
func durableRename(oldPath, newPath string) error {
	from, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
