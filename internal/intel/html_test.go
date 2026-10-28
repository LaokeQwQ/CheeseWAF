package intel

import (
	"strings"
	"testing"
)

const sampleAdvisoryHTML = `<!doctype html>
<html>
<head>
  <title>Advisory &amp; Notes</title>
  <style>body { color: red; }</style>
  <script>alert('xss')</script>
</head>
<body>
  <h1>PHP2Shell advisory</h1>
  <p>Upload a multipart request with <code>PHP_SESSION_UPLOAD_PROGRESS</code>.</p>
  <noscript>enable javascript now</noscript>
  <pre>curl -F "PHPSESSID=@x" https://target/upload.php</pre>
  <template><p>template marker</p></template>
  <p>End of advisory.</p>
</body>
</html>`

func TestExtractHTMLStripsScriptsAndStyles(t *testing.T) {
	document, err := ExtractHTML([]byte(sampleAdvisoryHTML), 0)
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	if document.Title != "Advisory & Notes" {
		t.Fatalf("unexpected title %q", document.Title)
	}
	for _, forbidden := range []string{"alert('xss')", "color: red", "enable javascript", "template marker"} {
		if strings.Contains(document.Text, forbidden) {
			t.Fatalf("text retained stripped content %q: %q", forbidden, document.Text)
		}
	}
	if !strings.Contains(document.Text, "PHP2Shell advisory") {
		t.Fatalf("text missing advisory content: %q", document.Text)
	}
	if !strings.Contains(document.Text, "End of advisory.") {
		t.Fatalf("text missing trailing content: %q", document.Text)
	}
	joined := strings.Join(document.CodeBlocks, "\n")
	if !strings.Contains(joined, "PHP_SESSION_UPLOAD_PROGRESS") {
		t.Fatalf("inline code block missing: %v", document.CodeBlocks)
	}
	if !strings.Contains(joined, "curl -F") {
		t.Fatalf("pre code block missing: %v", document.CodeBlocks)
	}
	if len(document.SHA256) != 64 {
		t.Fatalf("expected 64-char sha256, got %q", document.SHA256)
	}
}

func TestExtractHTMLTruncates(t *testing.T) {
	document, err := ExtractHTML([]byte(sampleAdvisoryHTML), 40)
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	if !document.Truncated {
		t.Fatal("expected truncated document")
	}
	if len(document.Text) > 40 {
		t.Fatalf("expected at most 40 text bytes, got %d", len(document.Text))
	}
}

func TestExtractHTMLRejectsEmptyInput(t *testing.T) {
	if _, err := ExtractHTML(nil, 0); err == nil {
		t.Fatal("expected empty input to be rejected")
	}
}

func TestExtractHTMLHashIsDeterministic(t *testing.T) {
	first, err := ExtractHTML([]byte(sampleAdvisoryHTML), 0)
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	second, err := ExtractHTML([]byte(sampleAdvisoryHTML), 0)
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	if first.SHA256 != second.SHA256 {
		t.Fatalf("hash is not deterministic: %q != %q", first.SHA256, second.SHA256)
	}
	changed, err := ExtractHTML([]byte(strings.Replace(sampleAdvisoryHTML, "End of advisory.", "Changed advisory.", 1)), 0)
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	if changed.SHA256 == first.SHA256 {
		t.Fatal("hash did not change when content changed")
	}
}

func TestExtractHTMLPlainText(t *testing.T) {
	document, err := ExtractHTML([]byte("CVE-2026-12345 is exploited in the wild"), 0)
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	if document.Title != "" {
		t.Fatalf("expected empty title, got %q", document.Title)
	}
	if !strings.Contains(document.Text, "CVE-2026-12345") {
		t.Fatalf("plain text was not retained: %q", document.Text)
	}
}
