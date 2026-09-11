//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenConfigFileAllowsRenameWhileReadHandleOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cheesewaf.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: ':8080'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := openConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	moved := filepath.Join(dir, "cheesewaf.yaml.moved")
	if err := os.Rename(path, moved); err != nil {
		t.Fatalf("rename with open config handle: %v", err)
	}
}
