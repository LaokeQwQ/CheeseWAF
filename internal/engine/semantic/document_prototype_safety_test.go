package semantic

import (
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestDocumentFormattingCannotSuppressExecutableXSS(t *testing.T) {
	cases := []struct{ name, body string }{
		{"html-block-code-span", "<div>\n`<script>alert(1)</script>`\n</div>"},
		{"paragraph-indentation", "Ordinary paragraph\n    <script>alert(1)</script>\n"},
		{"indented-fence", "Example\n\n    ```html\n<script>alert(1)</script>\n"},
		{"mixed-executable-patterns", "```html\n<script>alert(1)</script>\n```\n<img src=x onerror=alert(document.cookie)>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ResetProcessCacheForTest()
			result := detectOnTarget(t, NewAnalyzer("block", 3, "xss"), "POST", "/render", "text/markdown", tc.body)
			if result == nil || result.Action != engine.ActionBlock {
				t.Fatalf("executable Markdown must block: %+v", result)
			}
		})
	}
}

func TestDocumentMediaTypeCannotEstablishRenderer(t *testing.T) {
	body := "```html\n<script>alert(document.cookie)</script>\n```"
	for _, ct := range []string{"text/markdown", "text/plain", "text/html", "application/json"} {
		t.Run(ct, func(t *testing.T) {
			ResetProcessCacheForTest()
			result := detectOnTarget(t, NewAnalyzer("block", 3, "xss"), "POST", "/render", ct, body)
			if result == nil || result.Action != engine.ActionBlock {
				t.Fatalf("unknown downstream renderer must block despite client media type: %+v", result)
			}
		})
	}
}

func TestDocumentKeywordsCannotSuppressHTML(t *testing.T) {
	body := strings.Repeat("This security analysis explains the attack example and its mitigation. ", 5) + "<script>alert(1)</script>" + strings.Repeat(" This security analysis explains the attack example and its mitigation.", 5)
	ResetProcessCacheForTest()
	result := detectOnTarget(t, NewAnalyzer("block", 3, "xss"), "POST", "/render", "text/html", body)
	if result == nil || result.Action != engine.ActionBlock {
		t.Fatalf("executable HTML must block despite documentation keywords: %+v", result)
	}
}
