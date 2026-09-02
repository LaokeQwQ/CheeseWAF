package cli

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPIDLeaseIsExclusiveAndPublishesIdentityRecord(t *testing.T) {
	runtimeDir := t.TempDir()
	first, err := acquirePIDLease(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Write(os.Getpid()); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	second, err := acquirePIDLease(runtimeDir)
	if err == nil {
		_ = second.Close()
		_ = first.Close()
		t.Fatal("second service acquired the live PID lease")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err = acquirePIDLease(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := readPIDRecord(runtimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed lease should remove its PID before new write, got %v", err)
	}
	if err := second.Write(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	record, err := readPIDRecord(runtimeDir)
	if err != nil || record.PID != os.Getpid() || record.Executable == "" {
		t.Fatalf("unexpected PID record: %+v err=%v", record, err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, pidLeaseFileName)); err != nil {
		t.Fatalf("lease file missing: %v", err)
	}
}

func TestEnsureAuthSecretRejectsUnsafeExistingFilesAndRacesCreation(t *testing.T) {
	base := t.TempDir()
	secret, err := ensureAuthSecret(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 32 {
		t.Fatalf("generated secret too short: %d", len(secret))
	}
	info, err := os.Lstat(authSecretPath(base))
	if err != nil {
		t.Fatalf("stat generated auth.key: %v", err)
	}
	if err := validateAuthSecretFilePermissions(authSecretPath(base), info); err != nil {
		t.Fatalf("generated auth.key permissions: %v", err)
	}
	if got, err := ensureAuthSecret(base); err != nil || got != secret {
		t.Fatalf("stable auth secret = %q err=%v", got, err)
	}

	unsafe := filepath.Join(t.TempDir(), "auth.key")
	if err := os.WriteFile(unsafe, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureAuthSecret(filepath.Dir(unsafe)); err == nil {
		t.Fatal("accepted undersized auth.key")
	}
	symlinkBase := t.TempDir()
	target := filepath.Join(symlinkBase, "target")
	if err := os.WriteFile(target, []byte("valid-but-not-used"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, authSecretPath(symlinkBase)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ensureAuthSecret(symlinkBase); err == nil {
		t.Fatal("accepted symlink auth.key")
	}

	raceBase := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan string, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := ensureAuthSecret(raceBase)
			if err != nil {
				errs <- err
				return
			}
			results <- got
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for got := range results {
		if got != secret && got == "" {
			t.Fatal("empty raced auth secret")
		}
	}
}
