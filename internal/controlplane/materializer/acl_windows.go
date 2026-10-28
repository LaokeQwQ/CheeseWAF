//go:build windows

package materializer

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// privateDirectorySDDLPattern grants full control to SYSTEM, Builtin
// Administrators, the stored owner, and the account actually running the
// process. The running account must be explicit: when an administrator owns an
// existing directory, OW refers to that owner and would drop the service
// account's access.
const privateDirectorySDDLPattern = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;FA;;;%s)"

// ensurePrivateWindowsACL applies and verifies the private DACL for a journal
// directory. Without it, another local user could write receipts even though
// the requested mode says 0700.
func ensurePrivateWindowsACL(path string) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(privateDirectorySDDLPattern, sid))
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
