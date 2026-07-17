package handler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestACMECertificateSnapshotRestoresExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, "site.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	snapshot, err := snapshotACMECertificate(dir)
	if err != nil {
		t.Fatalf("snapshot certificate: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("new-cert"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("new-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.restore(); err != nil {
		t.Fatalf("restore certificate: %v", err)
	}
	assertFileContent(t, certPath, "old-cert")
	assertFileContent(t, keyPath, "old-key")
}

func TestACMECertificateSnapshotRemovesNewFiles(t *testing.T) {
	dir := t.TempDir()
	snapshot, err := snapshotACMECertificate(dir)
	if err != nil {
		t.Fatalf("snapshot empty certificate directory: %v", err)
	}
	for _, name := range []string{"fullchain.cer", "site.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := snapshot.restore(); err != nil {
		t.Fatalf("restore empty certificate state: %v", err)
	}
	for _, name := range []string{"fullchain.cer", "site.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("new certificate file %s should be removed, err=%v", name, err)
		}
	}
}

func TestACMECertificateSnapshotRejectsSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside-cert")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "fullchain.cer")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := snapshotACMECertificate(dir); err == nil {
		t.Fatal("expected symlink certificate target to be rejected")
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s content=%q want=%q", filepath.Base(path), got, want)
	}
}
