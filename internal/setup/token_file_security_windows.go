//go:build windows

package setup

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const setupTokenFileAllAccess = windows.ACCESS_MASK(0x001F01FF)

func protectSetupSecretFile(path string) error {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
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

	trustees := uniqueSetupTokenSIDs(currentUser.User.Sid, localSystem, administrators)
	var sddl strings.Builder
	sddl.WriteString("D:P")
	for _, trustee := range trustees {
		fmt.Fprintf(&sddl, "(A;;FA;;;%s)", trustee.String())
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl.String())
	if err != nil {
		return fmt.Errorf("build setup secret ACL: %w", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read setup secret ACL: %w", err)
	}
	if dacl == nil || defaulted {
		return fmt.Errorf("setup secret ACL is unavailable")
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		currentUser.User.Sid,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("protect setup secret ACL: %w", err)
	}
	return nil
}

func replaceSetupSecretFile(source, target string) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPath, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePath, targetPath, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func validateSetupSecretFilePermissions(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read setup secret security descriptor: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("setup secret security descriptor is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read setup secret ACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("setup secret ACL is inherited")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read setup secret ACL: %w", err)
	}
	if dacl == nil || defaulted {
		return fmt.Errorf("setup secret ACL is unavailable")
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read setup secret owner: %w", err)
	}
	if owner == nil || ownerDefaulted {
		return fmt.Errorf("setup secret owner is unavailable")
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	trustees := uniqueSetupTokenSIDs(owner, localSystem, administrators)
	if dacl.AceCount != uint16(len(trustees)) {
		return fmt.Errorf("setup secret ACL has unexpected entries: got %d, want %d", dacl.AceCount, len(trustees))
	}
	seen := make(map[string]bool, len(trustees))
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read setup secret ACL entry %d: %w", index, err)
		}
		if ace == nil {
			return fmt.Errorf("setup secret ACL entry %d is unavailable", index)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != setupTokenFileAllAccess {
			return fmt.Errorf("setup secret ACL entry %d is not an expected full-access grant", index)
		}
		actual := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := false
		for _, trustee := range trustees {
			if actual.Equals(trustee) {
				key := trustee.String()
				if seen[key] {
					return fmt.Errorf("setup secret ACL repeats trustee %q", key)
				}
				seen[key] = true
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("setup secret ACL grants unexpected trustee %q", actual.String())
		}
	}
	for _, trustee := range trustees {
		if !seen[trustee.String()] {
			return fmt.Errorf("setup secret ACL is missing trustee %q", trustee.String())
		}
	}
	return nil
}

func uniqueSetupTokenSIDs(values ...*windows.SID) []*windows.SID {
	seen := make(map[string]bool, len(values))
	unique := make([]*windows.SID, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		key := value.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, value)
	}
	return unique
}
