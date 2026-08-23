//go:build windows

package cli

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectAuthSecretFile(path string) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", user.User.Sid.String()),
	)
	if err != nil {
		return fmt.Errorf("build auth secret ACL: %w", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read auth secret ACL: %w", err)
	}
	if dacl == nil || defaulted {
		return fmt.Errorf("auth secret ACL is unavailable")
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("protect auth secret ACL: %w", err)
	}
	return nil
}

func validateAuthSecretFilePermissions(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read auth secret security descriptor: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("auth secret security descriptor is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read auth secret ACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("auth secret ACL is inherited")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read auth secret ACL: %w", err)
	}
	if dacl == nil || defaulted || dacl.AceCount != 3 {
		return fmt.Errorf("auth secret ACL is broader than expected")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	for _, trustee := range []*windows.SID{user.User.Sid, localSystem, administrators} {
		if !authSecretACLContainsSID(dacl, trustee) {
			return fmt.Errorf("auth secret ACL is missing required trustee %q", trustee.String())
		}
	}
	return nil
}

func authSecretACLContainsSID(acl *windows.ACL, expected *windows.SID) bool {
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		actual := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if actual.Equals(expected) {
			return true
		}
	}
	return false
}
