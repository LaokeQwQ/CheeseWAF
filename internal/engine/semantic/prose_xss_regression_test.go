package semantic

import (
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestExecutableHTMLWithProseRemainsBlockable(t *testing.T) {
	body := strings.Repeat("This is ordinary text around the embedded content. ", 4) + "<script>alert(document.cookie)</script>" + strings.Repeat("The remaining text describes the content for readers. ", 4)
	for level := 3; level <= 5; level++ {
		got := detectOnTarget(t, NewAnalyzer("block", level, "xss"), "POST", "/render", "text/html", body)
		if got == nil || got.Action != engine.ActionBlock {
			t.Fatalf("level %d executable HTML was downgraded: %+v", level, got)
		}
	}
}
