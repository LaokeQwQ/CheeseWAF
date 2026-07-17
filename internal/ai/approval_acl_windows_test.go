//go:build windows

package ai

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestApprovalPersistenceKeepsProtectedACLAfterAtomicReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := NewPersistentApprovalStore(path)
	if err != nil {
		t.Fatalf("create persistent store: %v", err)
	}
	for index := 0; index < 2; index++ {
		if _, err := store.CreateFor(fakeTool{sensitivity: Modify}, map[string]any{"index": index}, "", ApprovalActor{}); err != nil {
			t.Fatalf("persist approval %d: %v", index, err)
		}
		assertProtectedApprovalACL(t, path)
	}
}

func assertProtectedApprovalACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read approval file security descriptor: %v", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		t.Fatal("approval file security descriptor is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read approval file security descriptor control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("approval file DACL is not protected: %s", descriptor.String())
	}

	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("resolve current Windows user: %v", err)
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read approval file DACL: %v", err)
	}
	if dacl == nil || defaulted || dacl.AceCount != 3 {
		t.Fatalf("approval file DACL is broader than expected: defaulted=%v ace_count=%d sddl=%s", defaulted, dacl.AceCount, descriptor.String())
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("resolve LocalSystem SID: %v", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("resolve Administrators SID: %v", err)
	}
	for name, trustee := range map[string]*windows.SID{
		"current user":   currentUser.User.Sid,
		"LocalSystem":    localSystem,
		"Administrators": administrators,
	} {
		if !aclContainsSID(dacl, trustee) {
			t.Fatalf("approval file DACL does not contain %s SID %q: %s", name, trustee.String(), descriptor.String())
		}
	}
}

func aclContainsSID(acl *windows.ACL, expected *windows.SID) bool {
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
