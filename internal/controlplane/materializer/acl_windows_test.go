//go:build windows

package materializer

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The journal DACL must be protected and must explicitly allow the account
// running the process; an owner-only ACE fails for a service account that does
// not own the directory.
func TestEnsurePrivateWindowsACLGrantsRunningAccount(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateWindowsACL(dir); err != nil {
		t.Fatalf("apply ACL: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	assertDACLGrant(t, dir, sd)
	// Receipts created under the directory must inherit the restricted DACL.
	receipt := filepath.Join(dir, JournalPrimaryName)
	if err := os.WriteFile(receipt, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptSD, err := windows.GetNamedSecurityInfo(receipt, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	assertDACLGrant(t, receipt, receiptSD)
}

func assertDACLGrant(t *testing.T, path string, sd *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s: DACL is not protected", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: read DACL: %v", path, err)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	want := user.User.Sid.String()
	// FILE_ALL_ACCESS, the mask SDDL FA expands to.
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.String() == want && ace.Mask&fileAllAccess == fileAllAccess {
			return
		}
	}
	t.Fatalf("%s: DACL does not grant the running account %s", path, want)
}
