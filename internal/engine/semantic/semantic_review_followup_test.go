package semantic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestReviewDuplicateJSONRawRunsStructuredNoSQLAnalysis(t *testing.T) {
	for _, body := range []string{
		`{"user":{"$ne":null},"user":"alice"}`,
		`{"apikey":{"$ne":null},"apikey":"ordinary"}`,
		`{"user":{"\u0024ne":null},"user":"alice"}`,
	} {
		candidate := semanticCandidate{input: InputPoint{Source: "body.json.raw", Name: "body"}, text: body}
		if _, ok := analyzeNoSQL(candidate); !ok {
			t.Errorf("first duplicate operator was not inspected: %s", body)
		}
		for _, contentType := range []string{"application/json", "application/merge-patch+json", "text/plain"} {
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			ctx := &engine.RequestContext{Request: req, DecodedBody: []byte(body)}
			result, err := NewNoSQLiDetector("block").Detect(context.Background(), ctx)
			if err != nil || result == nil || !result.Detected {
				t.Errorf("duplicate operator under %s lost explicit detection: result=%+v err=%v", contentType, result, err)
			}
		}
	}
	for _, body := range []string{
		`{"docs":"MongoDB $ne operator example","docs":"ordinary text"}`,
		`{"user":"alice","user":"bob"}`,
	} {
		candidate := semanticCandidate{input: InputPoint{Source: "body.json.raw", Name: "body"}, text: body}
		if _, ok := analyzeNoSQL(candidate); ok {
			t.Errorf("benign duplicate body was detected: %s", body)
		}
	}
}

func TestReviewJSONRawWholeBodyContexts(t *testing.T) {
	if !nosqlStructuredSource("body.json.raw") {
		t.Error("raw JSON source is not reachable by NoSQL analysis")
	}
	candidate := semanticCandidate{input: InputPoint{Source: "body.json.raw", Name: "body"}}
	if !xxePayloadContext(candidate, `<!doctype root [<!entity x system "file:///etc/passwd">]><root>&x;</root>`) {
		t.Error("raw JSON body lost XML payload context")
	}
	candidate.text = `{"items":[]} /* inventory total */`
	if !sqlJSONTrailingCommentContext(candidate) {
		t.Error("raw JSON body lost whole-body trailing-comment context")
	}
}

func TestReviewLFIWrapperScansOccurrencesWithinToken(t *testing.T) {
	for _, text := range []string{
		`php://x php://filter/convert.base64-encode/resource=index.php`,
		`expect://is x file:///etc/shadow`,
		`file://x file:///etc/shadow`,
		`zip://x phar://archive.phar/index.php`,
		`php://x php://input`,
	} {
		if !lfiWrapperPathShape(text) {
			t.Errorf("decoy hid a later wrapper: %q", text)
		}
		if _, ok := analyzeLFI(semanticCandidate{input: InputPoint{Source: "query", Name: "file"}, text: text}); !ok {
			t.Errorf("later wrapper did not reach LFI detection: %q", text)
		}
	}
	for _, text := range []string{
		`php://filter is documented with resource= in the next section`,
		`file:// is documented at /docs/wrappers`,
		`zip://archive is documented at /docs/wrappers`,
		"zip://archive\u00a0is documented at /docs/wrappers",
		`expect://is documented here`,
		`php://inputting ordinary text`,
	} {
		if lfiWrapperPathShape(text) {
			t.Errorf("wrapper borrowed resource syntax outside its token: %q", text)
		}
	}
}

func TestReviewDuplicateKeyCheckerHasResourceLimits(t *testing.T) {
	deep := strings.Repeat("[", maxJSONDepth+2) + `{"x":1,"x":2}` + strings.Repeat("]", maxJSONDepth+2)
	if jsonHasDuplicateKeys([]byte(deep)) {
		t.Fatal("duplicate checker continued past its nesting budget")
	}
	var wide strings.Builder
	wide.WriteByte('{')
	for i := 0; i < maxJSONNodes*4; i++ {
		fmt.Fprintf(&wide, `"k%d":null,`, i)
	}
	wide.WriteString(`"x":1,"x":2}`)
	if jsonHasDuplicateKeys([]byte(wide.String())) {
		t.Fatal("duplicate checker continued past its token budget")
	}
	if !jsonHasDuplicateKeys([]byte(`{"a":{"x":1,"\u0078":2}}`)) {
		t.Fatal("bounded checker missed an ordinary escaped duplicate key")
	}
	// Stay below the byte budget so this exercises the nesting bound itself.
	raw := []byte(strings.Repeat("[", maxJSONTreeDecodeBytes/2))
	if allocs := testing.AllocsPerRun(1, func() { jsonHasDuplicateKeys(raw) }); allocs > 128 {
		t.Fatalf("deep prefix still caused input-sized frame allocation: %.0f allocations", allocs)
	}
}

func TestReviewJSONDepthKeepsLaterSiblings(t *testing.T) {
	for _, size := range []int{0, maxJSONTreeDecodeBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := `{"a":` + strings.Repeat("[", maxJSONDepth+2) + `"ignored"` + strings.Repeat("]", maxJSONDepth+2)
			if size > 0 {
				body += `,"padding":"` + strings.Repeat("a", size) + `"`
			}
			body += `,"user":{"$ne":null}}`
			var inputs []InputPoint
			status := flattenJSONInputsWithStatus("body.json", "", []byte(body), &inputs)
			if !status.omitted || status.reason != jsonDepthLimitIncompleteReason {
				t.Fatalf("depth omission was lost: %+v", status)
			}
			for _, input := range inputs {
				if input.Name == "user.$ne" {
					if _, ok := analyzeNoSQL(semanticCandidate{input: input, text: input.Raw}); !ok {
						t.Fatal("later sibling lost structural NoSQL detection")
					}
					return
				}
			}
			t.Fatalf("later sibling was dropped after a deep subtree: inputs=%d", len(inputs))
		})
	}
}
