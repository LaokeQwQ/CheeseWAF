package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBrowserURLUsesFragmentAndLoopback(t *testing.T) {
	got := BrowserURL("https", "0.0.0.0:9443", "secret with+symbols")
	want := "https://127.0.0.1:9443/setup#setup_token=secret+with%2Bsymbols"
	if got != want {
		t.Fatalf("BrowserURL() = %q, want %q", got, want)
	}
}

func TestWriteAndRemoveURL(t *testing.T) {
	dir := t.TempDir()
	page := BrowserURL("http", "127.0.0.1:9443", "tok")
	if err := WriteURL(dir, page); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, URLFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "setup_token=tok") {
		t.Fatalf("file = %q", raw)
	}
	if err := RemoveURL(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, URLFileName)); !os.IsNotExist(err) {
		t.Fatalf("expected file gone, err=%v", err)
	}
}

func TestWriteURLWithReceiptUsesPrivateAtomicEnvelope(t *testing.T) {
	dir := t.TempDir()
	page := BrowserURL("http", "127.0.0.1:9443", "tok")
	receipt, err := WriteURLWithReceipt(dir, page)
	if err != nil {
		t.Fatal(err)
	}
	if receipt == "" || receipt == "tok" {
		t.Fatalf("receipt = %q, want an opaque non-secret receipt", receipt)
	}

	path := filepath.Join(dir, URLFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("setup URL mode = %o, want 600", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, "url="+page) {
		t.Fatalf("setup URL envelope omitted page: %q", content)
	}
	if !strings.Contains(content, "receipt="+receipt) {
		t.Fatalf("setup URL envelope omitted receipt: %q", content)
	}
	if !strings.Contains(content, "expires_at=") {
		t.Fatalf("setup URL envelope omitted expiry: %q", content)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".setup.url-") {
			t.Fatalf("atomic setup URL temporary file survived: %s", entry.Name())
		}
	}
}

func TestWriteURLReplacesExistingBroadPermissionFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, URLFileName)
	if err := os.WriteFile(path, []byte("stale setup_token=old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteURL(dir, BrowserURL("http", "127.0.0.1:9443", "new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("replaced setup URL mode = %o, want 600", got)
	}
}

func TestWriteURLRejectsNewlineInjection(t *testing.T) {
	dir := t.TempDir()
	if err := WriteURL(dir, "http://127.0.0.1:9443/setup\nsetup_token=leak"); err == nil {
		t.Fatal("newline-bearing setup URL must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, URLFileName)); !os.IsNotExist(err) {
		t.Fatalf("rejected URL must not create a file, stat err=%v", err)
	}
}

func TestReadURLOnceConsumesURLAndRejectsReplay(t *testing.T) {
	dir := t.TempDir()
	page := BrowserURL("http", "127.0.0.1:9443", "tok")
	if _, err := WriteURLWithReceipt(dir, page); err != nil {
		t.Fatal(err)
	}
	got, err := ReadURLOnce(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != page {
		t.Fatalf("ReadURLOnce() = %q, want %q", got, page)
	}
	if _, err := os.Stat(filepath.Join(dir, URLFileName)); !os.IsNotExist(err) {
		t.Fatalf("one-time read must remove setup URL, stat err=%v", err)
	}
	if _, err := ReadURLOnce(dir); !errors.Is(err, ErrURLNotFound) {
		t.Fatalf("replayed setup URL error = %v, want ErrURLNotFound", err)
	}
}

func TestReadURLOnceReclaimsExpiredURL(t *testing.T) {
	dir := t.TempDir()
	page := BrowserURL("http", "127.0.0.1:9443", "tok")
	if _, err := WriteURLWithReceipt(dir, page); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, URLFileName)
	old := time.Now().Add(-(SetupURLTTL + time.Minute))
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadURLOnce(dir); !errors.Is(err, ErrURLExpired) {
		t.Fatalf("expired setup URL error = %v, want ErrURLExpired", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired setup URL must be reclaimed, stat err=%v", err)
	}
}

func TestExpireURLDoesNotDeleteNewerReceipt(t *testing.T) {
	dir := t.TempDir()
	page := BrowserURL("http", "127.0.0.1:9443", "tok")
	first, err := WriteURLWithReceipt(dir, page)
	if err != nil {
		t.Fatal(err)
	}
	second, err := WriteURLWithReceipt(dir, page)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("receipts must be unique across URL rewrites")
	}
	expireURL(dir, first)
	if _, err := os.Stat(filepath.Join(dir, URLFileName)); err != nil {
		t.Fatalf("stale expiry timer removed newer URL: %v", err)
	}
	expireURL(dir, second)
	if _, err := os.Stat(filepath.Join(dir, URLFileName)); !os.IsNotExist(err) {
		t.Fatalf("matching expiry must remove URL, stat err=%v", err)
	}
}
