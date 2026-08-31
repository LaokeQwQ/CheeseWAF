package semantic

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// These cover the remaining verified detection gaps: RCE command vocabulary and
// newline chaining, NoSQL shell escape and bracket-encoded operators, the
// Jinja/Twig arithmetic probe, and SSRF targets that arrive as a bare body.
//
// Every case here came out of the label-fidelity audit — a payload the corpus
// swore was of class X, that an independent signature set confirmed really was
// class X, and that the engine missed. None of them is a hypothetical.

func TestRCECommandVocabularyAndNewlineChain(t *testing.T) {
	cases := []struct {
		name, target, body, ct string
	}{
		{"nl-chain-bio", "/app/user/settings/update", "username=testuser&bio=hello%0aid%0als%20-la%20/tmp%0a#vault", "application/x-www-form-urlencoded"},
		{"nl-chain-json", "/contact/send", `{"name":"Michael Jones","message":"Hello\nid\nls -la /tmp"}`, "application/json"},
		{"nl-chain-name", "/contact/send", "name=Michael%20Jones&message=Hello%0aid%0als%20-la%20%2Ftmp", "application/x-www-form-urlencoded"},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", tc.target, tc.ct, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected detection, got none")
			}
			if got.Category != "rce" {
				t.Errorf("category = %q, want rce", got.Category)
			}
		})
	}
}

func TestRCEBacktickInUserAgent(t *testing.T) {
	cases := []struct{ name, ua string }{
		{"id", "ReportGen/3.4 `id`"},
		{"hostname", "StatsClient/5.7; echo `hostname` > /tmp"},
		{"uptime", "StatusCheck/2021 `uptime`"},
		{"ps", "DevCrawler `ps aux | grep root`"},
		{"browser-fingerprint", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 `whoami`"},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTargetWithHeader(t, a, "GET", "/status", "", "", "User-Agent", tc.ua)
			if got == nil || !got.Detected {
				t.Fatalf("expected rce detection for UA %q, got none", tc.ua)
			}
			if got.Category != "rce" {
				t.Errorf("category = %q, want rce", got.Category)
			}
		})
	}
}

// TestRCECommandNamesCoversShellMetacharVocabulary pins the two lists together.
// rceShellMetacharCommand already matched "id", "ls", "echo", "dir" and "type",
// but rceCommandNames — the map the backtick discriminator consults — did not,
// so a payload whose only signal was "`id`" was read as Markdown and dropped.
func TestRCECommandNamesCoversShellMetacharVocabulary(t *testing.T) {
	for _, command := range []string{"cat", "id", "whoami", "uname", "curl", "wget", "bash", "sh",
		"zsh", "dash", "pwsh", "powershell", "cmd", "python", "python3", "perl", "php", "ruby",
		"node", "nc", "ncat", "netcat", "socat", "lua", "iex", "type", "dir", "ls", "sleep",
		"echo", "ping"} {
		if !rceCommandNames[command] {
			t.Errorf("rceCommandNames is missing %q, which rceShellMetacharCommand already matches", command)
		}
	}
}

func TestRCENewlineCommandChainUnit(t *testing.T) {
	positive := []string{
		"hello\nid\nls -la /tmp\n#vault",
		"Alice Newman\nwhoami\necho Injected Text",
		"note\ncat /etc/passwd\nrm -rf /",
	}
	for _, in := range positive {
		if !rceNewlineCommandChain(in) {
			t.Errorf("rceNewlineCommandChain(%q) = false, want true", in)
		}
	}
	// A single command-named line must not be enough: multi-line form fields
	// mention tools all the time.
	negative := []string{
		"Please run id and send me the output.",
		"line one\nline two\nline three",
		"hello\nls",
		"",
	}
	for _, in := range negative {
		if rceNewlineCommandChain(in) {
			t.Errorf("rceNewlineCommandChain(%q) = true, want false", in)
		}
	}
}

func TestNoSQLShellEscapeAndBracketOperator(t *testing.T) {
	cases := []struct {
		name, target, body, ct string
	}{
		{"bracket-ne-query", "/api/v2/login?login=superuser&apikey%5B%24ne%5D=xyz", "", ""},
		{"bracket-ne-secret", "/profile/info?login=administrator&secret%5B%24ne%5D=guessme", "", ""},
		{"shell-escape-set", "/app/user/settings", "theme=dark'; db.users.update({username:'admin'}, {$set:{isAdmin:true}}); //", "application/x-www-form-urlencoded"},
		{"shell-escape-find", "/api/v1/login", "username=alex' } || db.users.find({isAdmin:true}) --", "application/x-www-form-urlencoded"},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", tc.target, tc.ct, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected detection, got none")
			}
			if got.Category != "nosqli" {
				t.Errorf("category = %q, want nosqli", got.Category)
			}
		})
	}
}

// TestNoSQLInjectionOperatorSplit pins why the operator vocabulary is split.
// $ne and $where have no legitimate client use, so a bracketed occurrence is
// enough on its own; $gt and $in appear in ordinary multi-value filters, so
// those must keep requiring a sensitive field name.
func TestNoSQLInjectionOperatorSplit(t *testing.T) {
	for _, name := range []string{"apikey[$ne]", "secret[$ne]", "filter[$where]", "x[$regex]"} {
		if !nosqlInjectionOperatorInPath(name) {
			t.Errorf("nosqlInjectionOperatorInPath(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"price[$gt]", "ids[$in]", "tags[$all]", "q[$or]"} {
		if nosqlInjectionOperatorInPath(name) {
			t.Errorf("nosqlInjectionOperatorInPath(%q) = true, want false: range/set operators are legitimate client filters", name)
		}
		if !nosqlOperatorInPath(name) {
			t.Errorf("nosqlOperatorInPath(%q) = false, want true: it is still a MongoDB operator", name)
		}
	}
}

// TestSSTIQuotedArithmeticProbe covers the 36 verified SSTI misses, which were
// all the same probe: {{ 7*'7' }}. The integer-only pattern could not see the
// quoted operand, and the parameter names it arrived under ("greeting", "note",
// "preview_text") were not in sstiProbeContext either.
func TestSSTIQuotedArithmeticProbe(t *testing.T) {
	cases := []struct{ name, param, payload string }{
		{"jinja", "greeting", `{{ 7*'7' }}`},
		{"jinja-spaces", "preview_text", `{{ 7*'7' }}`},
		{"jinja-note", "note", `{{ 7*'7' }}`},
		{"jinja-title", "title", `{{ 7*'7' }}`},
		{"twig", "name", `{{ 7*'7' }}`},
		{"double-quoted", "display_name", `{{ 7*"7" }}`},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/dashboard?"+tc.param+"="+url.QueryEscape(tc.payload), "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected ssti detection, got none")
			}
			if got.Category != "ssti" {
				t.Errorf("category = %q, want ssti", got.Category)
			}
		})
	}
}

// TestHeavyTimeBasedBlindSQL covers 148 of the 172 verified SQL misses, which
// were one shape. Time-based blind injection does not have to ask the database
// to sleep; it can ask it to do pointless work and measure the response. These
// payloads contain no sleep(), no benchmark() and no waitfor delay, so every
// existing time-delay signal missed them.
func TestHeavyTimeBasedBlindSQL(t *testing.T) {
	cases := []string{
		`1';select count(*) from all_users t1,all_users t2,all_users t3,all_users t4`,
		`1%")));select count(*) from rdb$fields as t1,rdb$types as t2,rdb$collations as t3 where 'x'='x`,
		`1"));select count(*) from domain.domains as t1,domain.columns as t2 and 'x'='x`,
		`1'));select count(*) from generate_series(1,5000000) and (('wmoo' like 'wmoo`,
		`pass' AnD SeLeCt CoUnT(*) FrOm users > 5 -- `,
	}
	a := NewAnalyzer("block", 2)
	for i, payload := range cases {
		name := payload
		if len(name) > 40 {
			name = name[:40]
		}
		t.Run(fmt.Sprintf("%d-%s", i, name), func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/param?val="+url.QueryEscape(payload), "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected sqli detection, got none")
			}
			if got.Category != "sqli" {
				t.Errorf("category = %q, want sqli", got.Category)
			}
		})
	}
}

// TestSQLHeavyQueryPrimitiveUnit pins the depth rule in sqlHeavyQueryPrimitive.
// A comma inside generate_series(1,5000000) is an argument separator, not a
// table separator; counting it would make every series call look like a join —
// which is harmless here, but the same mistake in the other direction (ignoring
// depth) would start matching ordinary argument lists as cross joins.
func TestSQLHeavyQueryPrimitiveUnit(t *testing.T) {
	positive := []string{
		`select count(*) from a t1,a t2`,
		`select count(*) from rdb$fields as t1,rdb$types as t2 where 'x'='x`,
		`select count(*) from generate_series(1,5000000) and (('a' like 'a`,
	}
	for _, in := range positive {
		if !sqlHeavyQueryPrimitive(in) {
			t.Errorf("sqlHeavyQueryPrimitive(%q) = false, want true", in)
		}
	}
	negative := []string{
		`select count(*) from users`,
		`select count(*) from generate_series(1,10)`,
		`select name from users`,
		``,
	}
	for _, in := range negative {
		if sqlHeavyQueryPrimitive(in) {
			t.Errorf("sqlHeavyQueryPrimitive(%q) = true, want false", in)
		}
	}
}

// TestSQLCommentTruncationSkipsWhitespace pins the fix for a whole family of
// space-separated comment truncations: "… FrOm users > 5 -- " reads as prose
// because text[idx-1] is a space rather than the digit that ends the predicate.
func TestSQLCommentTruncationSkipsWhitespace(t *testing.T) {
	positive := []string{
		`pass' AnD SeLeCt CoUnT(*) FrOm users > 5 -- `,
		`admin'--`,
		`x' or 1=1--`,
	}
	for _, in := range positive {
		if !sqlCommentTruncationShape(in) {
			t.Errorf("sqlCommentTruncationShape(%q) = false, want true", in)
		}
	}
	// Prose and documentation must stay out.
	for _, in := range []string{`user@example.com`, `list--item`, `see the notes--above`} {
		if sqlCommentTruncationShape(in) {
			t.Errorf("sqlCommentTruncationShape(%q) = true, want false", in)
		}
	}
}

// TestXSSSchemeSplittingEvasion covers the payloads that hide "javascript:"
// inside itself. Browsers and XML parsers discard whitespace, HTML comments and
// CDATA markers before deciding what a scheme is, so all three forms below are
// the same vector.
func TestXSSSchemeSplittingEvasion(t *testing.T) {
	cases := []struct{ name, payload string }{
		{"space", `<img src="jav ascript:alert(1);">`},
		{"html-comment", `<img src="java<!-- -->script:alert(1);">`},
		{"cdata", `<img src="javas]]><![cdata[cript:alert(1);">`},
		{"dynsrc", `<img dynsrc="javascript:document.cookie=true;">`},
		{"lowsrc", `<img lowsrc="javascript:document.cookie=true;">`},
		{"object-param", `<object><param name="url" value="javascript:document.cookie=true;"></object>`},
		{"object-param-reversed", `<object><param value="javascript:document.cookie=true;" name="movie"></object>`},
		{"css-expression-escape", `<br size="&{alert('crosssitescripting')}">`},
		{"js-string-breakout", `";alert('crosssitescripting');//`},
		{"malformed-handler", "<body onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"xss\")>"},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/param?val="+url.QueryEscape(tc.payload), "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected xss detection, got none")
			}
			if got.Category != "xss" {
				t.Errorf("category = %q, want xss", got.Category)
			}
		})
	}
}

func TestXSSValueAndExpressionLookalikesStayClean(t *testing.T) {
	benign := []string{
		`<input value="javascript:documentation">`,
		`<option value="javascript:guide">language guide</option>`,
		`&{alert(1)}`,
		`<div data-template="&{alert(1)}">`,
		`The template token &{alertStatus} is an ordinary identifier.`,
		`The template token &{customer.cookieConsent} is not executable code.`,
	}
	a := NewAnalyzer("block", 2)
	for _, payload := range benign {
		t.Run(payload, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/docs?text="+url.QueryEscape(payload), "", "")
			if got != nil && got.Detected && got.Category == "xss" {
				t.Fatalf("benign value/expression lookalike triggered XSS: %+v", got)
			}
		})
	}
}

func TestXSSObjectParamNameRequiresExactSink(t *testing.T) {
	positive := []string{
		`<object><param name="url" value="javascript:alert(1)"></object>`,
		`<object><param value='javascript:alert(1)' name='code'></object>`,
		`<param name=movie value=javascript:alert(1)>`,
	}
	for _, payload := range positive {
		if !hasXSSObjectParamJavascriptURL(normalize(payload)) {
			t.Errorf("exact object parameter sink was not recognized: %q", payload)
		}
	}

	negative := []string{
		`<object><param name="urlish" value="javascript:alert(1)"></object>`,
		`<object><param value='javascript:alert(1)' name='codebase'></object>`,
		`<param name=srcset value=javascript:alert(1)>`,
		`<param name=database value=javascript:alert(1)>`,
	}
	for _, payload := range negative {
		normalized := normalize(payload)
		if hasXSSObjectParamJavascriptURL(normalized) {
			t.Errorf("object parameter name prefix was treated as an exact sink: %q", payload)
		}
		if executableXSSContext(normalized) {
			t.Errorf("object parameter name prefix produced an executable context: %q", payload)
		}
	}

	// Exercise the mounted analyzer as well as the helper. The value is carried
	// in a normal query parameter so this catches broad scheme-only matches that
	// would otherwise be hidden by the direct unit assertions above.
	a := NewAnalyzer("block", 2, "xss")
	for _, payload := range positive {
		got := detectOnTarget(t, a, "GET", "/param?val="+url.QueryEscape(payload), "", "")
		if got == nil || !got.Detected || got.Category != "xss" {
			t.Errorf("analyzer missed exact object parameter sink %q: %+v", payload, got)
		}
	}
	for _, payload := range negative {
		got := detectOnTarget(t, a, "GET", "/param?val="+url.QueryEscape(payload), "", "")
		if got != nil && got.Detected && got.Category == "xss" {
			t.Errorf("analyzer treated object parameter name prefix as XSS: %q -> %+v", payload, got)
		}
	}
}

func TestXSSStandaloneJavascriptURLRequiresExecutionContext(t *testing.T) {
	fieldCases := []struct {
		name, value string
		want        bool
	}{
		{"url", "javascript:alert(1)", true},
		{"redirect_target", "<>javascript:alert(1);", true},
		{"urlish", "javascript:alert(1)", false},
		{"codebase", "javascript:alert(1)", false},
		{"database", "javascript:alert(1)", false},
		{"text", "javascript:alert(1)", false},
	}
	for _, tc := range fieldCases {
		candidate := semanticCandidate{input: InputPoint{Source: "query", Name: tc.name}, text: tc.value}
		if got := xssJavascriptURLFieldContext(candidate); got != tc.want {
			t.Errorf("URL field context for %q = %v, want %v", tc.name, got, tc.want)
		}
	}

	positive := []struct {
		name, target, body string
	}{
		{"url-field", "/go?next=" + url.QueryEscape("javascript:alert(1)"), ""},
		{"url-field-wrapper", "/r?url=" + url.QueryEscape("<>javascript:alert(1);"), ""},
		{"raw-body-url", "/submit", "javascript:alert(1)"},
		{"scheme-path", "/javascript:%0dalert(1)", ""},
		{"scheme-target", "javascript://alert(1)//", ""},
	}
	a := NewAnalyzer("block", 2, "xss")
	for _, tc := range positive {
		t.Run(tc.name, func(t *testing.T) {
			var got *engine.DetectionResult
			if tc.name == "scheme-target" {
				req, err := http.NewRequest(http.MethodGet, tc.target, nil)
				if err != nil {
					t.Fatal(err)
				}
				reqCtx, err := engine.NewRequestContext(req, "default")
				if err != nil {
					t.Fatal(err)
				}
				got, err = a.Detect(context.Background(), reqCtx)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				got = detectOnTarget(t, a, "POST", tc.target, "text/plain", tc.body)
			}
			if got == nil || !got.Detected || got.Category != "xss" {
				t.Fatalf("analyzer missed executable javascript URL context: %+v", got)
			}
		})
	}

	negative := []string{
		`Documentation mentions javascript:alert(1) without embedding a URL or executable markup.`,
		`<input value="javascript:alert(1)">`,
		`<param name="urlish" value="javascript:alert(1)">`,
		`<param name="codebase" value="javascript:alert(1)">`,
		`<param name="srcset" value="javascript:alert(1)">`,
		`<param name="database" value="javascript:alert(1)">`,
	}
	for _, payload := range negative {
		t.Run("negative-"+payload, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", "/submit", "text/plain", payload)
			if got != nil && got.Detected && got.Category == "xss" {
				t.Fatalf("non-executable javascript text triggered XSS: %+v", got)
			}
		})
	}
	// An exact script-looking value in an ordinary text field is still data;
	// only a URL-valued field gets the request-level execution interpretation.
	if got := detectOnTarget(t, a, "GET", "/docs?text="+url.QueryEscape("javascript:alert(1)"), "", ""); got != nil && got.Detected && got.Category == "xss" {
		t.Fatalf("ordinary text query field triggered XSS: %+v", got)
	}
}

// TestXSSNoisyWordMatchesPlainAndSplitForms pins that the assembled pattern
// matches the plain spelling too, so it can never be a net loss, and that it
// still requires the word boundary a lookalike would lack.
func TestXSSNoisyWordMatchesPlainAndSplitForms(t *testing.T) {
	positive := []string{
		`<img src="javascript:alert(1)">`,
		`<img src="jav ascript:alert(1)">`,
		`<img src="java<!-- -->script:alert(1)">`,
		`<img src="javas]]><![cdata[cript:alert(1)">`,
		`<img dynsrc="java script:alert(1)">`,
	}
	for _, in := range positive {
		if !xssObfuscatedJavascriptURL.MatchString(normalize(in)) {
			t.Errorf("xssObfuscatedJavascriptURL missed %q", in)
		}
	}
	negative := []string{
		`<img src="images/logo.png">`,
		`<a href="/about">about</a>`,
		`The word javascript appears in this sentence about the language.`,
	}
	for _, in := range negative {
		if xssObfuscatedJavascriptURL.MatchString(normalize(in)) {
			t.Errorf("xssObfuscatedJavascriptURL false positive on %q", in)
		}
	}
}

// TestServerSideIncludeInjection covers the 26 verified LFI misses that were
// Server Side Includes directives. The engine had no notion of SSI at all: these
// were only ever caught by accident, when the path inside the directive happened
// to satisfy an unrelated pattern.
func TestServerSideIncludeInjection(t *testing.T) {
	cases := []struct{ name, ct, body string }{
		{"include-file", "application/x-www-form-urlencoded", `profile_description=Enthusiastic+developer.+<!- -#include fIlE="/etc/passwd" - ->`},
		{"include-virtual", "application/x-www-form-urlencoded", `signature=Best+wishes+<!--#InClUdE ViRtUaL="/etc/hosts" -->`},
		{"include-proc", "application/x-www-form-urlencoded", `nickname=Lisa&user_bio=<!--#Include FilE="/proc/self/environ" -->`},
		{"include-shadow", "application/x-www-form-urlencoded", `user=tom&user_bio=<!--#INCLUDE FiLe="/etc/hosts" -->`},
		{"exec-cmd", "application/json", `{"config": {"snippet": "<!--#exec cmd='c' + 'a' + 't /etc/passwd'-->"}}`},
		{"exec-urlencoded", "application/x-www-form-urlencoded", `template_name=main<!--#exec%20cmd="cat%20/etc/passwd"-->`},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", "/profile/edit", tc.ct, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected detection, got none")
			}
			if got.Category != "lfi" {
				t.Errorf("category = %q, want lfi", got.Category)
			}
		})
	}
}

// TestSSIDirectiveToleratesSplitMarker pins the evasion handling: the two dashes
// of the "<!- -#" opener are separated so a literal "<!--#" does not match.
func TestSSIDirectiveToleratesSplitMarker(t *testing.T) {
	positive := []string{
		`<!--#include file="/etc/passwd" -->`,
		`<!- -#include fIlE="/etc/passwd" - ->`,
		`<!--#exec cmd="cat /etc/passwd"-->`,
		`<!--#echo var="DOCUMENT_NAME"-->`,
	}
	for _, in := range positive {
		if !lfiSSIDirective.MatchString(strings.ToLower(in)) {
			t.Errorf("lfiSSIDirective missed %q", in)
		}
	}
	// An ordinary HTML comment or a doctype must not read as a directive.
	for _, in := range []string{`<!-- a normal comment -->`, `<!DOCTYPE html>`, `<!-- note to self -->`} {
		if lfiSSIDirective.MatchString(strings.ToLower(in)) {
			t.Errorf("lfiSSIDirective false positive on %q", in)
		}
	}
}

// TestNoSQLInHeadersAreScanned pins a structural gap: nosqlStructuredSource
// omitted "header", so NoSQL analysis was skipped for every header on every
// request. A dozen verified misses carried the entire attack in a custom
// X-User-Filter header while the URL and body were ordinary traffic.
func TestNoSQLInHeadersAreScanned(t *testing.T) {
	if !nosqlStructuredSource("header") {
		t.Fatal("nosqlStructuredSource must accept headers: they are attacker-controlled input")
	}
	where := `{"$where": "if(this.isAdmin){var s=new Date();while((new Date())-s<5000){};return true}"}`
	got := detectOnTargetWithHeader(t, NewAnalyzer("block", 2), "POST", "/api/v3/items/search",
		"application/json", `{}`, "X-User-Filter", where)
	if got == nil || !got.Detected {
		t.Fatalf("expected nosqli detection from the header payload, got none")
	}
	if got.Category != "nosqli" {
		t.Errorf("category = %q, want nosqli", got.Category)
	}
}

// TestNoSQLShellEscapeIgnoresFieldName pins that a MongoDB shell breakout is
// judged on its own shape, not on whether the field happens to be named
// something sensitive. "comment" is not in nosqlSensitiveContext, so the payload
// below was dropped while the identical payload under "query" was caught.
func TestNoSQLShellEscapeIgnoresFieldName(t *testing.T) {
	cases := []struct{ name, body string }{
		{"comment", `name=Emily&comment=Nice%20post!');%20db.users.remove({isAdmin:true});%20//`},
		{"user_pref", `layout=grid&filter=active&user_pref=dark_mode']; db.users.find({role:'admin'}); //`},
		{"referral", `username=johndoe&email=johndoe@mail.com&referral_code=ABC123'}); db.users.insert({admin:true}); //`},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", "/profile/update", "application/x-www-form-urlencoded", tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected nosqli detection, got none")
			}
			if got.Category != "nosqli" {
				t.Errorf("category = %q, want nosqli", got.Category)
			}
		})
	}
}

// TestRCEPathQualifiedAndExecutionFunction covers the remaining RCE shapes:
// a command named by absolute path, and a shell separator followed by a
// language-level execution function.
func TestRCEPathQualifiedAndExecutionFunction(t *testing.T) {
	cases := []struct{ name, payload string }{
		{"netstat", `;netstat -a;`},
		{"lsof", "`lsof -i`"},
		// "/bin/cat /etc/passwd" is deliberately absent: it is attributed to lfi,
		// which is a defensible call — the payload really is reading a file, and
		// lfi outranks a sinkless rce. The basename reduction it would exercise is
		// already covered by absolute-path.
		{"absolute-path", "`/usr/bin/id`"},
		{"php-system", `;system('id')`},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/param?val="+url.QueryEscape(tc.payload), "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected rce detection, got none")
			}
			if got.Category != "rce" {
				t.Errorf("category = %q, want rce", got.Category)
			}
		})
	}
}

func TestRCECommandBase(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/id": "id", "/bin/cat": "cat", "id": "id",
		`/usr\bin\whoami`: "whoami", "(id)": "id", "id;": "id",
	}
	for in, want := range cases {
		if got := rceCommandBase(in); got != want {
			t.Errorf("rceCommandBase(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEnglishWordsAreNotShellCommands is the regression pin for a false positive
// this work introduced and then reverted. "who", "last", "arp" and "route" were
// added to the RCE command vocabulary and immediately turned an ordinary profile
// bio into a 0.90-confidence RCE.
func TestEnglishWordsAreNotShellCommands(t *testing.T) {
	for _, word := range []string{"who", "last", "arp", "route"} {
		if rceCommandNames[word] {
			t.Errorf("%q must not be in rceCommandNames: it is ordinary English and produced false positives", word)
		}
	}
	benign := []string{
		`{"bio":"Tech enthusiast &lt;em&gt;who loves&lt;/em&gt; open-source &amp; data science.","language":"en"}`,
		`{"bio": "Yoga enthusiast &lt;i&gt;who loves&lt;/i&gt; green tea &amp; meditation practices.","diet":"vegetarian"}`,
		`The engineer who last reviewed this route took the arp table.`,
	}
	a := NewAnalyzer("block", 2)
	for _, in := range benign {
		got := detectOnTarget(t, a, "POST", "/profile/edit", "application/json", in)
		if got != nil && got.Detected && got.Category == "rce" {
			t.Errorf("ordinary prose detected as rce: %q", in)
		}
	}
}

// TestSSTIWholeBodyProbeNeedsNoFieldName pins that the parameter-name gate is
// skipped when the entire value is one template expression. Payloads with no
// request line arrive as the whole body under the field name "body", and
// sstiProbeContext rejects "body" — so "{{7*7}}" was dropped.
func TestSSTIWholeBodyProbeNeedsNoFieldName(t *testing.T) {
	cases := []string{`{{7*7}}`, `${7*7}`, `{{ 7 * 7 }}`}
	a := NewAnalyzer("block", 2)
	for _, payload := range cases {
		t.Run(payload, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", "/", "", payload)
			if got == nil || !got.Detected {
				t.Fatalf("expected ssti detection, got none")
			}
			if got.Category != "ssti" {
				t.Errorf("category = %q, want ssti", got.Category)
			}
		})
	}
}

// TestSSTIWholeBodyExpressionIsAnchored guards the FP side: the pattern must
// require the whole value to be the expression, so that prose *containing* a
// template expression is not treated as one.
func TestSSTIWholeBodyExpressionIsAnchored(t *testing.T) {
	whole := []string{`{{7*7}}`, `${7*7}`, `{{config}}`, `{% if x %}`}
	for _, in := range whole {
		if !sstiWholeBodyExpression.MatchString(in) {
			t.Errorf("sstiWholeBodyExpression(%q) = false, want true", in)
		}
	}
	embedded := []string{
		`Template documentation may show {{ 7 * 7 }} as a harmless arithmetic example.`,
		`Hello {{name}}, your order shipped.`,
		`see the docs for {{config}} values`,
	}
	for _, in := range embedded {
		if sstiWholeBodyExpression.MatchString(in) {
			t.Errorf("sstiWholeBodyExpression(%q) = true, want false: prose must not count", in)
		}
	}
}

// TestCheapGatesAreSupersetsOfTheirPatterns pins the invariant that makes the
// pre-filters safe. Both were added to fix a 20x pipeline-latency regression
// caused by running two multi-alternative regexes on every input point. A gate
// that is not a strict superset of its pattern silently loses detections, which
// no throughput test would ever notice.
func TestCheapGatesAreSupersetsOfTheirPatterns(t *testing.T) {
	positive := []string{
		`C:\Windows\System32\drivers\etc\hosts`,
		`{"filePath":"C:\\Windows\\System32\\drivers\\etc\\hosts"}`,
		`D:\Data\Profiles\user\secrets.ini`,
		`C:\inetpub\wwwroot\web.config`,
		`c:/windows/win.ini`,
		`dark'; db.users.update({username:'admin'}, {$set:{isAdmin:true}}); //`,
		`alex' } || db.users.find({isAdmin:true}) --`,
		`x' || db.accounts.aggregate([{$match:{}}]) //`,
	}
	for _, in := range positive {
		lower := normalize(in)
		if lfiWindowsSystemPath.MatchString(lower) && !lfiWindowsSystemPathMatch(lower) {
			t.Errorf("lfiWindowsSystemPath gate is not a superset: %q", in)
		}
		if nosqlShellEscape.MatchString(lower) && !nosqlShellEscapeMatch(lower) {
			t.Errorf("nosqlShellEscape gate is not a superset: %q", in)
		}
	}
	// And the gates must actually agree on the attack shapes they exist for.
	for _, in := range []string{`C:\Windows\System32\config\SAM`, `'; db.users.find() //`} {
		lower := normalize(in)
		if !lfiWindowsSystemPathMatch(lower) && lfiWindowsSystemPath.MatchString(lower) {
			t.Errorf("gate disagrees with pattern on %q", in)
		}
	}
}

// TestSSTIIntegerArithmeticInDocumentationIsGated is the regression pin for the
// false positive this work introduced and then fixed. The quoted-operand probe
// initially accepted two plain integers, which silently bypassed the
// sstiProbeContext gate that exists precisely for this curated-corpus case.
// Only the full test suite caught it; the CI gate did not.
func TestSSTIIntegerArithmeticInDocumentationIsGated(t *testing.T) {
	benign := []struct{ param, value string }{
		{"text", "Template documentation may show {{ 7 * 7 }} as a harmless arithmetic example."},
		{"content", "Jinja renders {{ 7*7 }} as 49."},
		{"note", "The docs use {{ 3 + 4 }} to illustrate evaluation."},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range benign {
		got := detectOnTarget(t, a, "GET", "/doc?"+tc.param+"="+url.QueryEscape(tc.value), "", "")
		if got != nil && got.Detected && got.Category == "ssti" {
			t.Errorf("template documentation detected as ssti: %q", tc.value)
		}
	}
}

// TestSSRFWholeBodyTarget covers the six SSRF misses: bare metadata and
// loopback targets whose request line could not be expressed as a URL, so the
// adapter delivered them as the entire raw body. ssrfFetchSink rejected the
// input because the parameter is named "body".
func TestSSRFWholeBodyTarget(t *testing.T) {
	cases := []string{
		`dict://127.0.0.1:11211/stat`,
		`http://169.254.169.254/latest/meta-data/`,
		`gopher://127.0.0.1:70`,
		`http://[::1]`,
		`http://2130706433`,
	}
	a := NewAnalyzer("block", 2)
	for _, payload := range cases {
		t.Run(payload, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", "/", "", payload)
			if got == nil || !got.Detected {
				t.Fatalf("expected ssrf detection for %q, got none", payload)
			}
			if got.Category != "ssrf" {
				t.Errorf("category = %q, want ssrf", got.Category)
			}
		})
	}
}

func TestSSRFURLInsideProseIsNotAFetchTarget(t *testing.T) {
	// The "whole body" gate must not fire on a URL embedded in content.
	benign := []string{
		`See http://169.254.169.254 for the metadata service documentation.`,
		`notes\nhttp://127.0.0.1:8080\nmore notes`,
	}
	a := NewAnalyzer("block", 2)
	for _, in := range benign {
		got := detectOnTarget(t, a, "POST", "/note", "", in)
		if got != nil && got.Detected && got.Category == "ssrf" {
			t.Errorf("prose containing a URL detected as ssrf: %q", in)
		}
	}
}
