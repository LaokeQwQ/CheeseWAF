//go:build windows

package ai

import (
	"path/filepath"
	"strings"
	"testing"

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
	sddl := descriptor.String()
	for _, trustee := range []string{currentUser.User.Sid.String(), "SY", "BA"} {
		if !strings.Contains(sddl, trustee) {
			t.Fatalf("approval file DACL does not contain trustee %q: %s", trustee, sddl)
		}
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read approval file DACL: %v", err)
	}
	if dacl == nil || defaulted || dacl.AceCount != 3 {
		t.Fatalf("approval file DACL is broader than expected: defaulted=%v ace_count=%d sddl=%s", defaulted, dacl.AceCount, sddl)
	}
}
