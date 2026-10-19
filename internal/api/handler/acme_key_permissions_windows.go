//go:build windows

package handler

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no POSIX owner/group/mode bits. Protect the key with a DACL
// granting full access only to the service account, LocalSystem, and local
// administrators, matching the other private runtime secrets.
func protectACMEPrivateKey(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	sddl := fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;%s)(A;;FA;;;%s)", user.User.Sid.String(), system.String(), admins.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build private key ACL: %w", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || dacl == nil || defaulted {
		if err != nil {
			return fmt.Errorf("read private key ACL: %w", err)
		}
		return fmt.Errorf("private key ACL is unavailable")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("protect private key ACL: %w", err)
	}
	return nil
}

func validateACMEPrivateKeyPermissions(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read private key ACL: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("private key ACL is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read private key ACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private key ACL is inherited")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil || dacl == nil || defaulted || dacl.AceCount != 3 {
		if err != nil {
			return fmt.Errorf("read private key ACL: %w", err)
		}
		return fmt.Errorf("private key ACL is broader than expected")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	for _, expected := range []*windows.SID{user.User.Sid, system, admins} {
		found := false
		for index := uint32(0); index < uint32(dacl.AceCount); index++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				continue
			}
			actual := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if actual.Equals(expected) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("private key ACL is missing required trustee %q", expected.String())
		}
	}
	return nil
}
