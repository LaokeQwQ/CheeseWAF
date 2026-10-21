//go:build windows

package captcha

import "testing"

func TestCapSecretDevicePathsAreRejectedBeforeOpen(t *testing.T) {
	for _, path := range []string{
		`\\.\pipe\cap-secret`, `\\?\pipe\cap-secret`,
		`\\localhost\pipe\cap-secret`, `\\?\UNC\localhost\PIPE\cap-secret`,
		`//./pipe/cap-secret`, `\\?\GLOBALROOT\Device\NamedPipe\cap-secret`,
	} {
		if !capSecretDevicePath(path) {
			t.Errorf("device path %q was not rejected", path)
		}
	}
	for _, path := range []string{`C:\secrets\cap`, `\\?\C:\secrets\cap`, `\\fileserver\secrets\cap`} {
		if capSecretDevicePath(path) {
			t.Errorf("ordinary file path %q was classified as a device", path)
		}
	}
}
