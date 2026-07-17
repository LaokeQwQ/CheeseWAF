//go:build linux || darwin

package assets

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpenLocalAssetFSCreatesMissingRootComponents(t *testing.T) {
	base := t.TempDir()
	first := filepath.Join(base, "one")
	second := filepath.Join(first, "two")
	root := filepath.Join(second, "assets")

	fs, err := openLocalAssetFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })

	for _, dir := range []string{first, second, root} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("created root component %s has mode %v, want directory 0700", dir, info.Mode())
		}
	}
}

func TestOpenLocalAssetFSRejectsAncestorRedirectBeforeCreatingDescendants(t *testing.T) {
	base := t.TempDir()
	external := t.TempDir()
	keep := filepath.Join(external, "keep")
	if err := os.Mkdir(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keep, "marker"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}

	redirect := filepath.Join(base, "redirect")
	makeTestDirectoryLink(t, external, redirect)
	root := filepath.Join(redirect, "one", "two", "three")
	before := snapshotDirectoryTree(t, external)

	fs, err := openLocalAssetFS(root)
	if err == nil {
		fs.Close()
		t.Fatal("root below an ancestor redirect was accepted")
	}

	after := snapshotDirectoryTree(t, external)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("redirect target changed during rejected root creation:\nbefore=%v\nafter=%v", before, after)
	}
}

func snapshotDirectoryTree(t *testing.T, root string) map[string]string {
	t.Helper()
	entries := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		entries[rel] = info.Mode().String()
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entries[rel] += ":" + string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
