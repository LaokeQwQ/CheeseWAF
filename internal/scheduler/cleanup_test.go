package scheduler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupOldFilesKeepsShortDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		path := filepath.Join(dir, fmt.Sprintf("access-%d.log", i))
		if err := os.WriteFile(path, []byte("log\n"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	if err := CleanupOldFiles(context.Background(), Task{Target: dir, Keep: 7, ManagedRoots: []string{dir}}); err != nil {
		t.Fatalf("CleanupOldFiles() error = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("short cleanup should keep all files, got %d", len(entries))
	}
}

func TestCleanupOldFilesKeepsNewestFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	base := time.Now().Add(-10 * time.Hour)
	for i := 0; i < 5; i++ {
		path := filepath.Join(dir, fmt.Sprintf("access-%d.log", i))
		if err := os.WriteFile(path, []byte("log\n"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		mod := base.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatalf("set fixture time: %v", err)
		}
	}

	if err := CleanupOldFiles(context.Background(), Task{Target: dir, Keep: 2, ManagedRoots: []string{dir}}); err != nil {
		t.Fatalf("CleanupOldFiles() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("access-%d.log", i))); !os.IsNotExist(err) {
			t.Fatalf("old file access-%d.log should be removed, err=%v", i, err)
		}
	}
	for i := 3; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("access-%d.log", i))); err != nil {
			t.Fatalf("new file access-%d.log should remain: %v", i, err)
		}
	}
}

func TestCleanupOldFilesLeavesUnmanagedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"notes.txt", "database.sqlite", "access-1.log", "access-2.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CleanupOldFilesWithResult(Task{Type: "cleanup", Target: dir, Keep: 1, ManagedRoots: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes.txt", "database.sqlite"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("unmanaged file %s was removed: %v", name, err)
		}
	}
}

func TestCleanupOldFilesRejectsTargetOutsideManagedRoots(t *testing.T) {
	managed := t.TempDir()
	outside := t.TempDir()
	path := filepath.Join(outside, "access-old.log")
	if err := os.WriteFile(path, []byte("log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := CleanupOldFilesWithResult(Task{Type: "cleanup", Target: outside, Keep: 1, ManagedRoots: []string{managed}})
	if err == nil {
		t.Fatal("expected cleanup outside managed roots to fail")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("cleanup touched file outside managed roots: %v", statErr)
	}
}

func TestCleanupOldFilesRejectsSymlinkEscape(t *testing.T) {
	managed := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(managed, "escaped")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	path := filepath.Join(outside, "access-old.log")
	if err := os.WriteFile(path, []byte("log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := CleanupOldFilesWithResult(Task{Type: "cleanup", Target: link, Keep: 1, ManagedRoots: []string{managed}})
	if err == nil {
		t.Fatal("expected symlink escape to fail")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("cleanup touched file through symlink escape: %v", statErr)
	}
}
