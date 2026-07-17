package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupConfigWritesVerifiedManagedManifest(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "cheesewaf.yaml")
	want := []byte("server:\n  listen: 9443\n")
	if err := os.WriteFile(source, want, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "backups")
	task := Task{ID: "backup", Type: "backup", Target: target}
	if err := BackupConfig(source, dir)(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), managedBackupSuffix) {
		t.Fatalf("unexpected backup files: %v", entries)
	}
	raw, err := os.ReadFile(filepath.Join(target, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var manifest BackupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(want)
	if manifest.Version != 1 || manifest.SHA256 != fmt.Sprintf("%x", sum[:]) || string(manifest.Content) != string(want) {
		t.Fatalf("invalid manifest: %+v", manifest)
	}
}
