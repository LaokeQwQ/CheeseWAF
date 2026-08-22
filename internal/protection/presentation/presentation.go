// Package presentation provides reversible display transforms.
//
// These functions do not encrypt, authenticate, or protect their input and
// must not be used as a security boundary.
package presentation

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// EncodeHTMLForScriptTransport wraps HTML in a browser-side base64 decoder.
// Base64 is an encoding, not encryption, and the original HTML remains public.
func EncodeHTMLForScriptTransport(html []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(html)
	return []byte(`<!doctype html><meta charset="utf-8"><script>document.write(atob("` + encoded + `"));</script><noscript>JavaScript is required.</noscript>`)
}

// MinifyJavaScript removes comments and surrounding line whitespace.
// It is a presentation transform, not code protection or obfuscation.
func MinifyJavaScript(source []byte) []byte {
	text := string(source)
	text = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(text, "")
	lines := strings.Split(text, "\n")
	for idx, line := range lines {
		lines[idx] = strings.TrimSpace(line)
	}
	return []byte(strings.Join(lines, ""))
}
