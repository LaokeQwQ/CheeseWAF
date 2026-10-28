//go:build windows

package materializer

import "golang.org/x/sys/windows"

// privateDirectorySDDL grants full control to SYSTEM, Builtin Administrators,
// and the owning user only, and marks the DACL protected so children inherit
// exactly this set. It replaces the POSIX 0700 guarantee on Windows.
const privateDirectorySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// ensurePrivateWindowsACL applies and verifies the private DACL for a journal
// directory. Without it, another local user could write receipts even though
// the requested mode says 0700.
func ensurePrivateWindowsACL(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString(privateDirectorySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
