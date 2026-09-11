package kms

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyringFileStoreCreatesPrivateAtomicFileAndRoundTrips(t *testing.T) {
	kr := mustKeyring(t, source{key: bytes.Repeat([]byte{0x76}, 32)})
	ref := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	if err := kr.Put(context.Background(), ref, bytes.Repeat([]byte{0x41}, 32)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "keyring.bin")
	if err := SaveKeyringFile(context.Background(), path, kr); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", st.Mode().Perm())
	}
	loaded, err := LoadKeyringFile(context.Background(), path, source{key: bytes.Repeat([]byte{0x76}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Get(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyringFile(context.Background(), path, kr); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("overwrite=%v", err)
	}
}

func TestKeyringFileStoreRejectsSymlinkAndTamperedDocument(t *testing.T) {
	kr := mustKeyring(t, source{key: bytes.Repeat([]byte{0x77}, 32)})
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyringFile(context.Background(), link, kr); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("symlink overwrite=%v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "sentinel" {
		t.Fatal("symlink target modified")
	}
	ref := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	if err := kr.Put(context.Background(), ref, bytes.Repeat([]byte{0x41}, 32)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ring")
	if err := SaveKeyringFile(context.Background(), path, kr); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyringFile(context.Background(), path, source{key: bytes.Repeat([]byte{0x77}, 32)}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered=%v", err)
	}
}
