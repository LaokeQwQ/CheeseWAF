package semantic

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func detectOnTarget(t *testing.T, a *Analyzer, method, target, ct, body string) *engine.DetectionResult {
	t.Helper()
	return detectOnTargetWithHeader(t, a, method, target, ct, body, "", "")
}

// detectOnTargetWithHeader builds a request context the way the rest of the
// package does and optionally sets one extra header. Header-borne payloads need
// it: several verified misses carried the attack in a User-Agent value.
func detectOnTargetWithHeader(t *testing.T, a *Analyzer, method, target, ct, body, header, value string) *engine.DetectionResult {
	t.Helper()
	req := httptest.NewRequest(method, "http://x"+target, strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if header != "" {
		req.Header.Set(header, value)
	}
	reqCtx := &engine.RequestContext{Request: req, DecodedBody: []byte(body), Metadata: map[string]any{}}
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	return got
}

// XPath injection was the single largest verified detection gap: 213 of the 676
// confirmed misses. The corpora file it under "sqli" and so does the engine,
// because it is the same breakout with a different grammar — but the engine
// modelled only the SQL grammar, so every XPath payload passed through.
func TestXPathInjectionDetected(t *testing.T) {
	cases := []struct {
		name, target, ct, body string
	}{
		{"count-wildcard", "/search", "application/xml", `<searchRequest><term>' or count(//*) > 0 or ''='</term></searchRequest>`},
		{"count-node", "/search", "application/xml", `<searchRequest><term>' or count(//node()) > 0 or ''='</term></searchRequest>`},
		{"form-substring", "/api/v1/auth", "application/x-www-form-urlencoded", `user=guest' and substring(//users/user[1]/concat(password,concat(//users/user[2]/email)),3,1)='m'&pass=dummy12`},
		{"form-substring-member", "/login/process", "application/x-www-form-urlencoded", `userid=player1' and substring(//members/member[1]/concat(password,string-length(//members/member[1]/password)),1,1)='a'`},
		{"json-substring", "/api/v1/search", "application/json", `{"q":"' and substring(//authors/author[1]/concat(password,substring(//authors/author[1]/password,3,1)),4,1)='e'"}`},
		{"query-substring", "/search?q=" + url.QueryEscape(`' and substring(//accounts/account[1]/phone,4,1)='7`), "", ""},
		{"query-count", "/search?q=" + url.QueryEscape(`x' or count(//*) > 0 or ''='`), "", ""},
		{"query-relative-path", "/xml_api/search_books?author_id=" + url.QueryEscape(`101' or string-length(user/password[1]) > 5 or 'a'='a`), "", ""},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", tc.target, tc.ct, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected sqli detection, got none")
			}
			if got.Category != "sqli" {
				t.Errorf("category = %q, want sqli", got.Category)
			}
		})
	}
}

// TestXPathLocationPathStepUnit pins the parser against the shapes that decide
// whether a "//" is a location path or ordinary text. Getting this wrong in
// either direction is expensive: too strict loses 213 attacks, too loose turns
// every URL and every Go doc comment into an injection.
func TestXPathLocationPathStepUnit(t *testing.T) {
	positive := []string{
		"count(//*)",
		"count(//node())",
		"//users/user[1]/concat(password)",
		"//members/member[1]/password",
		"//accounts/account[1]/phone",
		"//text()",
		"// *",
		"//user[name='admin']",
	}
	for _, in := range positive {
		if _, ok := xpathLocationPathStep(in); !ok {
			t.Errorf("xpathLocationPathStep(%q) = false, want true", in)
		}
	}

	// Ordinary text containing "//". These are the false-positive shapes the
	// parser has to survive, and they all appear in the curated corpus.
	negative := []string{
		"https://example.com/api/v1/users",
		"http://localhost:9443/setup",
		"// Package engine provides sandboxed execution guards.",
		"// TODO: revisit this",
		"see https://owasp.org/www-community/attacks/XPATH_Injection",
		"a // b",
		"/usr/local/bin",
		"",
	}
	for _, in := range negative {
		if step, ok := xpathLocationPathStep(in); ok {
			t.Errorf("xpathLocationPathStep(%q) = %q, want false", in, step)
		}
	}
}

// TestXPathInjectionShapeRequiresBothHalves pins the gate: a location path
// without XPath function grammar is not enough, because the same string can be
// a URL fragment or a doc comment that happens to sit near an identifier.
func TestXPathInjectionShapeRequiresBothHalves(t *testing.T) {
	if _, ok := xpathInjectionShape("//users/user[1]/password"); ok {
		t.Error("a location path with no XPath function must not be an injection shape")
	}
	if _, ok := xpathInjectionShape("concat('a','b')"); ok {
		t.Error("an XPath function with no location path must not be an injection shape")
	}
	if _, ok := xpathInjectionShape("' and substring(//users/user[1]/password,1,1)='a"); !ok {
		t.Error("path plus function must be an injection shape")
	}
	if _, ok := xpathInjectionShape("101' or string-length(user/password[1]) > 5 or 'a'='a"); !ok {
		t.Error("relative path plus quote breakout and comparison must be an injection shape")
	}
	for _, in := range []string{
		"string-length(user/password[1]) is documented here",
		"The user/password path is used by the parser.",
		"https://example.com/string-length(user/password)",
	} {
		if step, ok := xpathInjectionShape(in); ok {
			t.Errorf("relative XPath shape %q was too broad: %q", in, step)
		}
	}
}

func TestXPathMatchBracketNested(t *testing.T) {
	// A predicate that itself contains a bracket must close at the matching "]"
	// rather than at the first one.
	// xpathMatchBracket closes ONE bracket; xpathScanner.predicates loops to
	// consume the run. The nested "[...]" must therefore close at its own
	// matching "]" and leave "[1]" for the next loop iteration.
	in := "//user[substring(name,1,1)='a'][1]"
	got := xpathMatchBracket(in, strings.Index(in, "["))
	if want := strings.Index(in, "[1]"); got != want {
		t.Errorf("xpathMatchBracket = %d, want %d", got, want)
	}
	if got := xpathMatchBracket("//user[1", 6); got != -1 {
		t.Errorf("unbalanced bracket: got %d, want -1", got)
	}
}

// TestXPathPayloadsDoNotFireOnDocumentation is the FP guard that matters most
// for the curated corpus: security write-ups quote XPath payloads verbatim, and
// Go source files are full of "//". Neither is an attack.
func TestXPathPayloadsDoNotFireOnDocumentation(t *testing.T) {
	benign := []string{
		"https://example.com/search?q=users",
		"// Package search indexes documents by path.",
		"See https://owasp.org/xpath for background on count() and substring().",
		"/api/v1/items?page=1",
	}
	a := NewAnalyzer("block", 2)
	for _, in := range benign {
		got := detectOnTarget(t, a, "GET", "/search?q="+url.QueryEscape(in), "", "")
		if got != nil && got.Detected {
			t.Errorf("benign input %q detected as %s", in, got.Category)
		}
	}
}
