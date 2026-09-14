//go:build windows

package ota

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectStateFile(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", user.User.Sid.String()),
	)
	if err != nil {
		return fmt.Errorf("build state file ACL: %w", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read state file ACL: %w", err)
	}
	if dacl == nil || defaulted {
		return fmt.Errorf("state file ACL is unavailable")
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
		return fmt.Errorf("protect state file ACL: %w", err)
	}
	return nil
}

func replaceStateFileAtomic(source, target string) error {
	sourcePtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePtr, targetPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func validateStateFilePermissions(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read state file security descriptor: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("state file security descriptor is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read state file ACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("state file ACL is inherited")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read state file ACL: %w", err)
	}
	if dacl == nil || defaulted || dacl.AceCount != 3 {
		return fmt.Errorf("state file ACL is broader than expected")
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
		if !stateFileACLContainsSID(dacl, trustee) {
			return fmt.Errorf("state file ACL is missing required trustee %q", trustee.String())
		}
	}
	return nil
}

func stateFileACLContainsSID(acl *windows.ACL, expected *windows.SID) bool {
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
