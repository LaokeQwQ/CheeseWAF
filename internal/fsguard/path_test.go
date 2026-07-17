package fsguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeConfigPath(t *testing.T) {
	for _, path := range []string{"", "a\x00b", "a\nb"} {
		if _, err := SafeConfigPath(path); err == nil {
			t.Fatalf("SafeConfigPath(%q) want error", path)
		}
	}
	dir := t.TempDir()
	got, err := SafeConfigPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("not absolute: %q", got)
	}
}

func TestSafeConfigPathUnderRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "keys", "a.pem")
	if err := os.MkdirAll(filepath.Dir(inside), 0o700); err != nil {
		t.Fatal(err)
	}
	// File need not exist; RelUnderRoot + evalExistingPrefix must still work on macOS.
	if _, err := SafeConfigPathUnderRoot(inside, root); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeConfigPathUnderRoot(filepath.Join(root, "keys", "a.pem"), root); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "escape.pem")
	if _, err := SafeConfigPathUnderRoot(outside, root); err == nil {
		t.Fatal("expected escape outside root to fail")
	}
}

func TestRelUnderRootRejectsEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := RelUnderRoot(root, filepath.Join(root, "..", "x")); err == nil {
		t.Fatal("expected .. escape to fail")
	}
	if _, err := RelUnderRoot(root, "/etc/passwd"); err == nil {
		t.Fatal("expected absolute outside root to fail")
	}
}

func TestReadFileUnderRoot(t *testing.T) {
	root := t.TempDir()
	name := "secret.json"
	body := []byte(`{"ok":true}`)
	if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFileUnderRoot(root, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %s", got)
	}
	if _, err := ReadFileUnderRoot(root, "../secret.json", 0); err == nil {
		t.Fatal("expected traversal to fail")
	}
}

func TestSafePathComponent(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "a b"} {
		if err := SafePathComponent(name); err == nil {
			t.Fatalf("SafePathComponent(%q) want error", name)
		}
	}
	if err := SafePathComponent("asset.bin"); err != nil {
		t.Fatal(err)
	}
}

func TestSanitizeLocalRedirect(t *testing.T) {
	cases := map[string]string{
		"":                      "/",
		"/":                     "/",
		"/ok":                   "/ok",
		"/ok?x=1":               "/ok?x=1",
		"//evil.test":           "/",
		"/\\evil":               "/",
		"https://evil.test/":    "/",
		"/ok\nSet-Cookie":       "/",
		"ok":                    "/ok",
		"/a/../b":               "/b",
		"/../b":                 "/",
		"/%5C%5Cevil.example/x": "/",
		"/%2F%2Fevil.example/x": "/",
	}
	for in, want := range cases {
		if got := SanitizeLocalRedirect(in); got != want {
			t.Fatalf("SanitizeLocalRedirect(%q)=%q want %q", in, got, want)
		}
	}
	// CodeQL second-character property on all non-root returns.
	for in := range cases {
		got := SanitizeLocalRedirect(in)
		if got == "/" {
			continue
		}
		if len(got) < 2 || got[0] != '/' || got[1] == '/' || got[1] == '\\' {
			t.Fatalf("SanitizeLocalRedirect(%q)=%q fails second-char rule", in, got)
		}
	}
}
