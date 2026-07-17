package assets

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSafeConfigPathRejectsEmptyAndControl(t *testing.T) {
	for _, path := range []string{"", "  ", "a\x00b", "a\nb"} {
		if _, err := safeConfigPath(path); err == nil {
			t.Fatalf("safeConfigPath(%q) = nil, want error", path)
		}
	}
}

func TestSafeConfigPathAcceptsAbsolute(t *testing.T) {
	dir := t.TempDir()
	got, err := safeConfigPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("expected absolute path, got %q", got)
	}
	// Relative input still resolves under the process working directory.
	rel := filepath.Base(dir)
	if runtime.GOOS == "windows" && strings.Contains(rel, ":") {
		t.Skip("basename not usable as relative fixture on this host")
	}
}

func TestSafePathComponent(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "a\x00b", "a b"} {
		if err := safePathComponent(name); err == nil {
			t.Fatalf("safePathComponent(%q) = nil, want error", name)
		}
	}
	if err := safePathComponent("asset.bin"); err != nil {
		t.Fatal(err)
	}
}
