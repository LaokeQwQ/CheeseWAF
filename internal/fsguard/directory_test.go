package fsguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDirectoryUnderRootAllowsMissingDirectories(t *testing.T) {
	base := t.TempDir()
	for _, tc := range []struct{ name, root, target string }{
		{"existing root", base, filepath.Join(base, "reports", "daily")},
		{"root itself", base, base},
		{"missing root", filepath.Join(base, "data"), filepath.Join(base, "data", "reports")},
		{"missing ancestors", filepath.Join(base, "fresh", "install", "data"), filepath.Join(base, "fresh", "install", "data", "reports")},
		{"missing root itself", filepath.Join(base, "empty"), filepath.Join(base, "empty")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDirectoryUnderRoot(tc.root, tc.target); err != nil {
				t.Fatalf("safe future directory was rejected: %v", err)
			}
			if tc.target != base {
				if _, err := os.Stat(tc.target); !os.IsNotExist(err) {
					t.Fatalf("validation must not create directories, got %v", err)
				}
			}
		})
	}
}

func TestValidateDirectoryUnderRootRejectsSymlinksAndFiles(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "data")
	outside := t.TempDir()
	inside := filepath.Join(root, "real")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, link, dest, target string }{
		{"external link", filepath.Join(root, "escape"), outside, filepath.Join(root, "escape", "reports")},
		{"internal link", filepath.Join(root, "alias"), inside, filepath.Join(root, "alias", "reports")},
		{"dangling link", filepath.Join(root, "dangling"), filepath.Join(outside, "missing"), filepath.Join(root, "dangling", "reports")},
		{"root symlink", filepath.Join(base, "root-link"), root, filepath.Join(base, "root-link", "reports")},
		{"root symlink itself", filepath.Join(base, "root-self"), root, filepath.Join(base, "root-self")},
		{"missing root behind dangling link", filepath.Join(base, "missing-parent"), filepath.Join(outside, "missing"), filepath.Join(base, "missing-parent", "data", "reports")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Symlink(tc.dest, tc.link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			managedRoot := root
			if tc.name == "root symlink" || tc.name == "root symlink itself" {
				managedRoot = tc.link
			}
			if tc.name == "missing root behind dangling link" {
				managedRoot = filepath.Join(tc.link, "data")
			}
			if err := ValidateDirectoryUnderRoot(managedRoot, tc.target); err == nil {
				t.Fatal("existing symlink must be rejected even when the output is missing")
			}
		})
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{outside, filepath.Join(root, "..", "escape"), file, filepath.Join(file, "reports")} {
		if err := ValidateDirectoryUnderRoot(root, target); err == nil {
			t.Errorf("unsafe directory %q was accepted", target)
		}
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("validation changed external output: entries=%v err=%v", entries, err)
	}
}
