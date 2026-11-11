package semantic

import (
	"fmt"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestDocumentRepresentationsPreserveXSSDetection(t *testing.T) {
	for _, doc := range executableTechnicalDocuments {
		for _, ct := range []string{"text/markdown", "text/plain", "text/html", "application/json"} {
			for _, target := range []string{"/render", "/api/documents", "/upload"} {
				for _, variant := range []struct {
					name, body string
					block      bool
				}{
					{"raw", doc.body, true},
					{"fenced", "```html\n" + doc.body + "\n```", true},
					{"quoted", "> " + strings.ReplaceAll(doc.body, "\n", "\n> "), true},
					{"escaped", strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(doc.body), true},
				} {
					for level := 3; level <= 5; level++ {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/level%d", doc.name, ct, target, variant.name, level), func(t *testing.T) {
							got := detectOnTarget(t, NewAnalyzer("block", level, "xss"), "POST", target, ct, variant.body)
							blocked := got != nil && got.Action == engine.ActionBlock
							if blocked != variant.block {
								t.Fatalf("block=%v want %v result=%+v", blocked, variant.block, got)
							}
						})
					}
				}
			}
		}
	}
}
