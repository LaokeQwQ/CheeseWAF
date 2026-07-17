//go:build windows

package assets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestValidateWindowsComponent(t *testing.T) {
	for _, name := range []string{"asset.bin", ".asset-temp", "background"} {
		if err := validateWindowsComponent(name); err != nil {
			t.Errorf("validateWindowsComponent(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", `a\b`, "a/b", "a:b", "name.", "name ", "a\x00b"} {
		if err := validateWindowsComponent(name); err == nil {
			t.Errorf("validateWindowsComponent(%q) unexpectedly succeeded", name)
		}
	}
}

func TestWindowsHandleRelativeOpenAndRemove(t *testing.T) {
	fs, err := openLocalAssetFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err = fs.ensureKind(KindBackground); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fs.kindPath(KindBackground), "asset.bin")
	if err = os.WriteFile(path, []byte("captcha"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := fs.open(KindBackground, "asset.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = fs.remove(KindBackground, "asset.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err = fs.open(KindBackground, "asset.bin"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open after remove = %v, want os.ErrNotExist", err)
	}
}

func TestWindowsHandleRelativeOperationsRejectInvalidNames(t *testing.T) {
	fs, err := openLocalAssetFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err = fs.ensureKind(KindBackground); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`..\outside.bin`, "../outside.bin", "asset.bin:stream", "asset.bin.", "asset.bin "} {
		if _, err = fs.open(KindBackground, name); err == nil {
			t.Errorf("open(%q) unexpectedly succeeded", name)
		}
		if err = fs.remove(KindBackground, name); err == nil {
			t.Errorf("remove(%q) unexpectedly succeeded", name)
		}
	}
}

func TestWindowsNativeStructureABI(t *testing.T) {
	var rename windowsFileRenameInformation
	if got := unsafe.Offsetof(rename.FileName); got != 20 {
		t.Fatalf("FILE_RENAME_INFORMATION FileName offset = %d, want 20", got)
	}
	var dir windowsFileIDBothDirInfo
	if got := unsafe.Offsetof(dir.FileName); got != 104 {
		t.Fatalf("FILE_ID_BOTH_DIR_INFO FileName offset = %d, want 104", got)
	}
}

func TestWindowsAtomicWriteReplaceAndReadDir(t *testing.T) {
	fs, err := openLocalAssetFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err = fs.ensureKind(KindBackground); err != nil {
		t.Fatal(err)
	}
	if err = fs.atomicWrite(KindBackground, "asset.bin", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = fs.atomicWrite(KindBackground, "asset.bin", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fs.readFile(KindBackground, "asset.bin", 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("replacement content = %q, want new", got)
	}
	entries, err := fs.readDir(KindBackground)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "asset.bin" || entries[0].IsDir() {
		t.Fatalf("readDir entries = %#v", entries)
	}
	for _, name := range []string{"../escape", `..\escape`, "asset.bin:stream", "name."} {
		if err = fs.atomicWrite(KindBackground, name, []byte("bad"), 0o600); err == nil {
			t.Errorf("atomicWrite(%q) unexpectedly succeeded", name)
		}
	}
}

func TestWindowsRootPathReplacementDoesNotEscapeHandle(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	fs, err := openLocalAssetFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err = fs.ensureKind(KindBackground); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(base, "pinned")
	if err = os.Rename(root, pinned); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, string(KindBackground)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = fs.atomicWrite(KindBackground, "asset.bin", []byte("pinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(pinned, string(KindBackground), "asset.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pinned" {
		t.Fatalf("pinned content = %q", got)
	}
	if _, err = os.Stat(filepath.Join(root, string(KindBackground), "asset.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement path received file: %v", err)
	}
}

func TestWindowsOpenLocalAssetFSCreatesNestedDirectoryTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "one", "two", "three")
	fs, err := openLocalAssetFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatalf("nested root was not created: info=%v err=%v", info, err)
	}
}

func TestWindowsOpenLocalAssetFSRejectsAncestorReparsePoint(t *testing.T) {
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, "linked")
	makeTestDirectoryLink(t, target, link)
	fs, err := openLocalAssetFS(filepath.Join(link, "nested"))
	if err == nil {
		fs.Close()
		t.Fatal("root below ancestor reparse point was accepted")
	}
	if _, statErr := os.Stat(filepath.Join(target, "nested")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("reparse target was modified: %v", statErr)
	}
}

func TestWindowsLocalAssetFSCloseIsIdempotentAndDisablesOperations(t *testing.T) {
	fs, err := openLocalAssetFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = fs.Close(); err != nil {
		t.Fatal(err)
	}
	if err = fs.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if err = fs.ensureKind(KindBackground); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ensureKind after Close = %v, want os.ErrClosed", err)
	}
}

func TestWindowsAtomicWriteFailureCleansTemporaryFile(t *testing.T) {
	fs, err := openLocalAssetFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err = fs.ensureKind(KindBackground); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(fs.kindPath(KindBackground), "asset.bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = fs.atomicWrite(KindBackground, "asset.bin", []byte("data"), 0o600); err == nil {
		t.Fatal("atomicWrite unexpectedly replaced a directory")
	}
	entries, err := os.ReadDir(fs.kindPath(KindBackground))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".asset-") {
			t.Fatalf("temporary file remained after failure: %s", entry.Name())
		}
	}
}
