//go:build linux || darwin

package assets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStoreTightensExistingDirectoryPermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "assets")
	if err := os.MkdirAll(filepath.Join(root, string(KindBackground)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, string(KindBackground)), 0o755); err != nil {
		t.Fatal(err)
	}

	fs, err := openLocalAssetFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.ensureKind(KindBackground); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{root, filepath.Join(root, string(KindBackground))} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("directory %s permissions = %o, want 700", path, got)
		}
	}
}
