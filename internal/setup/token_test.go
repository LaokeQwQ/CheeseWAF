package setup

import (
	"os"
	"testing"
)

func TestTokenStoreRotateRevokesPreviousValue(t *testing.T) {
	store := NewTokenStore(t.TempDir())
	first, err := store.Ensure("")
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if first == "" {
		t.Fatal("Ensure() returned an empty token")
	}
	rotated, err := store.Rotate()
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if rotated == first {
		t.Fatal("Rotate() reused the previous token")
	}
	if got := store.Current(); got != rotated {
		t.Fatalf("Current() = %q, want rotated token", got)
	}

	info, err := os.Stat(TokenFilePath(store.dataDir))
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if err := validateSetupSecretFilePermissions(TokenFilePath(store.dataDir), info); err != nil {
		t.Fatalf("token file permissions are not private: %v", err)
	}

	if err := store.Remove(); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if got := store.Current(); got != "" {
		t.Fatalf("Current() after Remove() = %q, want empty", got)
	}
}
