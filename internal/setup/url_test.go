package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
