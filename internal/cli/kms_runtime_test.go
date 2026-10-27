package cli

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/recovery/kms"
)

func writeRootKey(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "root.key")
	if err := os.WriteFile(path, key, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func embeddedKMSConfig(t *testing.T, dir string) config.KMSConfig {
	t.Helper()
	return config.KMSConfig{
		Enabled:  true,
		TenantID: "tenant-a",
		KeyID:    "key-a",
		Scope:    "envelope",
		Actor:    "diagnostics",
		Embedded: config.EmbeddedKMSConfig{
			Approved:    true,
			Mode:        "single-node",
			RootKeyFile: writeRootKey(t, dir, 0o600),
			KeyringFile: filepath.Join(dir, "keyring.enc"),
		},
	}
}

func TestOpenKMSRuntimeEmbeddedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := embeddedKMSConfig(t, dir)
	runtime, closer, err := openKMSRuntime(cfg, 9, "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()
	if runtime == nil {
		t.Fatal("runtime is nil")
	}
	if _, err := os.Stat(cfg.Embedded.KeyringFile); err != nil {
		t.Fatalf("keyring file was not created: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	wrapped, err := runtime.Wrap(context.Background(), "v1", dek)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := runtime.Unwrap(context.Background(), "v1", wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != string(dek) {
		t.Fatal("unwrap did not return the wrapped DEK")
	}
	if err := runtime.Rotate(context.Background(), "v1"); err == nil {
		t.Fatal("internal authorizer must deny rotation")
	}
	if err := runtime.Revoke(context.Background(), kms.Embedded, "v1"); err == nil {
		t.Fatal("internal authorizer must deny revocation")
	}
}

func TestOpenKMSRuntimeReloadsExistingKeyring(t *testing.T) {
	dir := t.TempDir()
	cfg := embeddedKMSConfig(t, dir)
	first, firstCloser, err := openKMSRuntime(cfg, 9, "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := first.Wrap(context.Background(), "v1", dek)
	if err != nil {
		t.Fatal(err)
	}
	if firstCloser != nil {
		_ = firstCloser.Close()
	}
	second, secondCloser, err := openKMSRuntime(cfg, 9, "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if secondCloser != nil {
			_ = secondCloser.Close()
		}
	}()
	plaintext, err := second.Unwrap(context.Background(), "v1", wrapped)
	if err != nil || string(plaintext) != string(dek) {
		t.Fatalf("reloaded keyring could not unwrap: %v", err)
	}
}

func TestOpenKMSRuntimeRejectsLooseRootKey(t *testing.T) {
	dir := t.TempDir()
	cfg := embeddedKMSConfig(t, dir)
	if err := os.Chmod(cfg.Embedded.RootKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openKMSRuntime(cfg, 9, "v1", nil); err == nil {
		t.Fatal("world-readable root key must be rejected")
	}
}

func TestKMSConfigRequiresEndpointOrApprovedEmbedded(t *testing.T) {
	cfg := config.Default()
	cfg.KMS = config.KMSConfig{Enabled: true, TenantID: "tenant-a", KeyID: "key-a", Scope: "envelope", Actor: "diagnostics"}
	if err := config.Validate(&cfg); err == nil {
		t.Fatal("kms without endpoint or approved embedded fallback must be rejected")
	}
	cfg.KMS = embeddedKMSConfig(t, t.TempDir())
	cfg.Diagnostics = config.DiagnosticsConfig{Enabled: true, Endpoint: "https://upload.example/v1", TokenFile: "/tmp/token", KeyVersion: "v1", TenantID: "tenant-a", Actor: "diagnostics", QueueDir: "/tmp/queue", Timeout: 5 * time.Second}
	if err := config.Validate(&cfg); err != nil {
		t.Fatalf("valid kms+diagnostics config rejected: %v", err)
	}
}
