package presentation

import (
	"bytes"
	"testing"
)

func TestEncodeHTMLForScriptTransportDoesNotClaimEncryption(t *testing.T) {
	encoded := EncodeHTMLForScriptTransport([]byte("<h1>ok</h1>"))
	if !bytes.Contains(encoded, []byte("atob")) || bytes.Contains(encoded, []byte("<h1>ok</h1>")) {
		t.Fatalf("HTML was not encoded for script transport: %s", encoded)
	}
}

func TestMinifyJavaScriptRemovesComments(t *testing.T) {
	out := MinifyJavaScript([]byte("/*x*/\nconst a = 1; // y\n"))
	if bytes.Contains(out, []byte("/*")) || bytes.Contains(out, []byte("//")) {
		t.Fatalf("comments were not removed: %s", out)
	}
}
