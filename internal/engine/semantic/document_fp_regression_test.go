package semantic

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// The document gate must downgrade, not silently drop: the evidence stays
// visible to review so tuning can see what was suppressed. This is the
// "log/review, not block" contract of the guard.
func TestDocumentationDowngradesToReviewNotBlock(t *testing.T) {
	const doc = `### Why input validation is not enough

I keep seeing developers strip the word UNION from input. That does not help:
the payload UNION SELECT 1,2,3 has many spellings, and stripping one keyword
leaves the rest intact. Parameterised queries are the only reliable fix.`
	a := NewAnalyzer("block", 3)
	req := httptest.NewRequest(http.MethodPost, "http://x/api/documents", strings.NewReader(doc))
	req.Header.Set("Content-Type", "text/markdown")
	reqCtx := &engine.RequestContext{Request: req, DecodedBody: []byte(doc), Metadata: map[string]any{}}
	got, err := a.Detect(t.Context(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("documentation was detected as a request: %+v", got)
	}
	review, ok := reqCtx.Metadata["review_candidate"].(map[string]any)
	if !ok || review == nil {
		t.Fatal("expected a review candidate so the downgrade stays observable")
	}
	if review["category"] != "sqli" {
		t.Fatalf("review category = %v, want sqli", review["category"])
	}
}

// C4 — technical documentation quotes attack syntax as subject matter.
//
// Every document below is an ordinary benign artifact: an API reference entry, a
// release note, a forum question, a source docstring, a blog post, a
// troubleshooting note, training slides, a detector coverage table, and two
// Chinese articles. Each one contains complete attack syntax inside explanatory
// prose, a fenced code block, or a table cell. At most two may be blocked at
// protection level 3; a value that *is* the payload must still block.
var benignTechnicalDocuments = []struct{ name, body string }{
	{"api-reference", `Path parameter: ` + "`file`" + `.

The endpoint streams a file from the storage bucket. Passing ../../etc/passwd
returns a 400 because the resolver rejects any segment that climbs above the
bucket root.`},
	{"release-notes", `## 4.2.0

Hardened the request normaliser. Requests whose path contains a matrix segment
such as /a/..;/b are now rejected with 400 instead of being cleaned silently.
Also blocked <script>alert(1)</script> in the echo endpoint.`},
	{"chinese-analysis", `## 路径穿越漏洞分析

当下载接口未校验文件名时，攻击者可以构造 ../../etc/passwd 这样的路径读取系统文件。
修复方式是先做路径规范化，再判断结果是否仍位于根目录之内。本文只做原理说明。`},
	{"chinese-cheatsheet", `# 常见攻击特征速查

| 类型 | 特征 |
| --- | --- |
| SQL 注入 | UNION SELECT 1,2,3 |
| XSS | <script>alert(1)</script> |
| 路径穿越 | ../../etc/passwd |
| 命令执行 | os.system('ls') |

上表用于日志排查，字符串本身不代表请求是攻击。`},
	{"forum-question", `Why does my scanner report this?

I ran a scanner against my own staging box and it flagged the string
UNION SELECT 1,2,3 that I pasted into a comment field while testing. Is that a
false positive? The comment field is stored as text and never reaches the
database query builder.`},
	{"source-docstring", `// SanitizePath rejects traversal sequences.
//
// Input such as ../../etc/passwd returns an error. The function never touches
// the filesystem; it only validates the string shape.
func SanitizePath(p string) error {`},
	{"blog-post", `### Why input validation is not enough

I keep seeing developers strip the word UNION from input. That does not help:
the payload UNION SELECT 1,2,3 has many spellings, and stripping one keyword
leaves the rest intact. Parameterised queries are the only reliable fix.`},
	{"troubleshooting", `Symptom: the upload endpoint returns 500.

Cause: the client sent a filename containing ../../etc/passwd. The service
correctly refused to write outside its directory and raised an error instead of
falling back. Fix the client, not the server.`},
	{"training-slide", `# Module 3: Injection

- SQL: UNION SELECT 1,2,3
- Shell: os.system('ls')
- Template: {{7*7}}

Each slide shows the string in a monospace box so trainees can recognise it in
logs. The lab environment is isolated and the examples are inert.`},
	{"detector-coverage", `## Detector coverage

| Detector | Sample input | Expected |
| --- | --- | --- |
| lfi | ../../etc/passwd | block |
| xss | <script>alert(1)</script> | block |
| sqli | UNION SELECT 1,2,3 | block |

The table is documentation for operators who tune the ruleset.`},
}

func TestTechnicalDocumentationFalsePositiveBudget(t *testing.T) {
	a := NewAnalyzer("block", 3)
	blocked := 0
	var blockedNames []string
	for _, doc := range benignTechnicalDocuments {
		got := detectOnTarget(t, a, "POST", "/api/documents", "text/markdown", doc.body)
		if got != nil && got.Action == engine.ActionBlock {
			blocked++
			blockedNames = append(blockedNames, doc.name+" ("+got.Category+")")
		}
	}
	if blocked > 2 {
		t.Fatalf("blocked %d/%d benign technical documents, want <= 2: %v",
			blocked, len(benignTechnicalDocuments), blockedNames)
	}
}

// The document gate must not become a bypass. A value that is nothing but the
// payload is a request, whatever its length, and must keep blocking.
func TestStandalonePayloadsStillBlock(t *testing.T) {
	a := NewAnalyzer("block", 3)
	cases := []struct{ name, method, target, ct, body string }{
		{"query-union", "GET", "/search?q=" + url.QueryEscape("UNION SELECT 1,2,3"), "", ""},
		{"query-xss", "GET", "/search?q=" + url.QueryEscape("<script>alert(1)</script>"), "", ""},
		{"query-lfi", "GET", "/search?q=" + url.QueryEscape("../../etc/passwd"), "", ""},
		{"raw-body-union", "POST", "/api/search", "text/plain", "UNION SELECT 1,2,3"},
		{"raw-body-lfi", "POST", "/api/search", "text/plain", "../../etc/passwd"},
		{"raw-body-xss", "POST", "/api/search", "text/plain", "<script>alert(1)</script>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, tc.method, tc.target, tc.ct, tc.body)
			if got == nil || !got.Detected || got.Action != engine.ActionBlock {
				t.Fatalf("standalone payload %q must still block, got %+v", tc.body, got)
			}
		})
	}
}

// A payload prefixed with prose but with nothing after it is still a request:
// the explanatory gate requires natural language on both sides.
func TestPayloadAfterProsePrefixStillBlocks(t *testing.T) {
	a := NewAnalyzer("block", 3)
	body := "Here is a long benign-looking introduction that pads the request body with ordinary words and then the attack follows: ../../etc/passwd"
	got := detectOnTarget(t, a, "POST", "/api/search", "text/plain", body)
	if got == nil || !got.Detected || got.Action != engine.ActionBlock {
		t.Fatalf("payload after a prose prefix must still block, got %+v", got)
	}
}
