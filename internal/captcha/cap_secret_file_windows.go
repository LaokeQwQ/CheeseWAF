//go:build windows

package captcha

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func statCapSecretFile(path string) (os.FileInfo, error) {
	if capSecretDevicePath(path) {
		return nil, errCapSecretFile
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return info, err
	}
	// Match the shared metadata-handle pattern used by knowledge files. Windows
	// SameFile lazily reopens Lstat metadata without sharing and can otherwise
	// reject a regular file while the reader holds it open.
	file, err := openCapSecretHandle(path, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func openCapSecretFile(path string) (*os.File, error) {
	return openCapSecretHandle(path, windows.GENERIC_READ)
}

func openCapSecretHandle(path string, access uint32) (*os.File, error) {
	if capSecretDevicePath(path) {
		return nil, errCapSecretFile
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	kind, err := windows.GetFileType(h)
	var info windows.ByHandleFileInformation
	if err != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(h, &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, errCapSecretFile
	}
	return os.NewFile(uintptr(h), path), nil
}

func capSecretDevicePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	if strings.HasPrefix(normalized, `\\.\`) || strings.HasPrefix(normalized, `\\?\globalroot\`) {
		return true
	}
	// Named-pipe shares are devices even when addressed using UNC syntax.
	if strings.HasPrefix(normalized, `\\`) {
		share := strings.TrimPrefix(normalized, `\\?\unc\`)
		share = strings.TrimPrefix(share, `\\`)
		parts := strings.SplitN(share, `\`, 3)
		return len(parts) >= 2 && parts[1] == "pipe"
	}
	return false
}
