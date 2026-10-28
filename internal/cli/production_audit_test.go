package cli

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The checkpoint signer must survive restarts and stay private; critical audit
// events cannot be appended without it.
func TestLoadAuditCheckpointSignerPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := loadAuditCheckpointSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit", checkpointSeedFile)
	seed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length = %d", len(seed))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("seed permissions = %v", info.Mode().Perm())
	}
	second, err := loadAuditCheckpointSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.PrivateKey.Equal(second.PrivateKey) {
		t.Fatal("reloading generated a different checkpoint key")
	}
}
