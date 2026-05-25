package crypto

import (
	"bytes"
	"testing"
)

func TestProtectHTMLEncodesBody(t *testing.T) {
	protected := ProtectHTML([]byte("<h1>ok</h1>"))
	if !bytes.Contains(protected, []byte("atob")) || bytes.Contains(protected, []byte("<h1>ok</h1>")) {
		t.Fatalf("html was not protected: %s", protected)
	}
}

func TestObfuscateJSRemovesComments(t *testing.T) {
	out := ObfuscateJS([]byte("/*x*/\nconst a = 1; // y\n"))
	if bytes.Contains(out, []byte("/*")) || bytes.Contains(out, []byte("//")) {
		t.Fatalf("comments were not removed: %s", out)
	}
}
