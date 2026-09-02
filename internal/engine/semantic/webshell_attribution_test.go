package semantic

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestWebshellDetectsURLDecodedFormInCompressedBody(t *testing.T) {
	plain := []byte(`x=%24_GET%5B%27fn%27%5D%28%24_GET%5B%27arg%27%5D%29`)
	for _, tc := range []struct {
		name   string
		encode func([]byte) ([]byte, error)
	}{
		{name: "gzip", encode: func(in []byte) ([]byte, error) {
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			if _, err := zw.Write(in); err != nil {
				return nil, err
			}
			if err := zw.Close(); err != nil {
				return nil, err
			}
			return b.Bytes(), nil
		}},
		{name: "deflate", encode: func(in []byte) ([]byte, error) {
			var b bytes.Buffer
			zw, err := flate.NewWriter(&b, flate.DefaultCompression)
			if err != nil {
				return nil, err
			}
			if _, err := zw.Write(in); err != nil {
				return nil, err
			}
			if err := zw.Close(); err != nil {
				return nil, err
			}
			return b.Bytes(), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.encode(plain)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "http://x/submit", io.NopCloser(bytes.NewReader(encoded)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Content-Encoding", tc.name)
			req.ContentLength = int64(len(encoded))
			reqCtx, err := engine.NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := engine.NewPipeline(NewWebshellDetector("block")).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				t.Fatalf("compressed %s form gadget was missed: %+v", tc.name, got)
			}
			if gotEncoding := req.Header.Get("Content-Encoding"); gotEncoding != tc.name {
				t.Fatalf("parent content encoding changed to %q", gotEncoding)
			}
			replayed, err := io.ReadAll(req.Body)
			if err != nil || !bytes.Equal(replayed, encoded) {
				t.Fatalf("parent transfer body was not preserved (len=%d, err=%v)", len(replayed), err)
			}
		})
	}
}

// TestWebshellRejectsSecurityDocuments pins the mined_probe FP that the ASPX
// branch produced: a structured POC writeup naming System.Diagnostics.Process in
// a sentence fired "syntax: ASP.NET process or dynamic evaluation primitive".
// A vulnerability disclosure that quotes a primitive is not a page that runs one.
//
// The separator is the ASP.NET server-side code delimiter, not
// securityDocumentContext. A document guard on this path reads text the attacker
// supplies in full and so acts as a suppression oracle — see
// TestWebshellDocumentGuardIsNotAnEvasionOracle. Each case below is therefore
// asserted against the mechanism that actually holds: no delimiter, no fire.
//
// Note the asymmetry with the PHP branch: a document that quotes a complete
// live one-liner (<?php eval($_POST['x']) — delimiter, primitive and superglobal
// all present) does fire, and that is intended. At that point the document
// contains a working shell body, and the only thing that could separate it is a
// suppression this path must not have.
func TestWebshellRejectsSecurityDocuments(t *testing.T) {
	docs := []struct {
		name string
		text string
	}{
		{
			name: "structured poc template quoting aspx primitive",
			text: "【漏洞类型】web_application_vulnerability\n" +
				"【POC利用方法】\n" +
				"1. app=\"畅捷通-TPlus\"\n" +
				"2. POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code\n" +
				"3. 该接口反序列化后进入 System.Diagnostics.Process 启动外部进程，\n" +
				"   攻击者可借此执行任意命令。建议升级到最新补丁版本并限制该路径访问。\n" +
				"【影响版本】TPlus 全版本\n【修复建议】升级补丁\n",
		},
		{
			name: "prose naming aspx primitive without delimiter",
			text: "The advisory notes that the deserialization sink eventually calls " +
				"System.Diagnostics.Process.Start with an attacker-controlled argument, " +
				"so operators should apply the vendor patch and restrict the endpoint.\n",
		},
		{
			name: "scanner report listing jsp primitives",
			text: "这是一个jsp类型的webshell文件。 检测到恶意函数: response.getWriter, " +
				"request.getParameter, Runtime.getRuntime() 恶意度评分: 9/20 " +
				"建议: 这是一个高风险的webshell文件，应立即删除并检查系统安全。",
		},
		{
			name: "conference slide on webshell research",
			text: "Webshell通常是打开权限大门的第一块破门砖 Java Webshell在攻防演练中占据着重要的地位 " +
				"随着各类防护设备不断升级如何逃避检测成为攻击者最关心的问题 常见的实现是 " +
				"Runtime.getRuntime().exec 配合 request.getParameter 取值。",
		},
	}

	for _, tc := range docs {
		t.Run(tc.name, func(t *testing.T) {
			normalized := strings.ToLower(tc.text)
			if aspxServerCodeContext(normalized) || jspServerCodeContext(normalized) {
				t.Fatalf("precondition failed: this document carries a server-side code delimiter, so the delimiter requirement is not what separates it")
			}
			if _, ok := analyzeWebshell(semanticCandidate{text: tc.text}); ok {
				t.Fatalf("analyzeWebshell flagged a security document as a webshell")
			}
		})
	}
}

// TestWebshellStillDetectsRealShells guards the revert direction: the ASPX
// server-side code requirement must not cost real detections. Each payload is an
// actual shell body or control request.
func TestWebshellStillDetectsRealShells(t *testing.T) {
	shells := []struct {
		name   string
		source string
		text   string
	}{
		{"php eval post", "body.raw", `<?php eval($_POST['cmd']); ?>`},
		{"php system get", "body.raw", `<?php system($_GET['c']); ?>`},
		{"php shortopen assert request", "body.raw", `<?= assert($_REQUEST['x']); ?>`},
		{"php base64 obfuscated cookie", "body.raw", `<?php eval(base64_decode($_COOKIE['p'])); ?>`},
		{"jsp runtime getparameter", "body.raw", `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`},
		{"jsp processbuilder param", "body.raw", `<% new ProcessBuilder(request.getParameter("c")).start(); %>`},
		{"jsp el param runtime", "body.raw", `<jsp:scriptlet>Runtime.getRuntime().exec("${param.cmd}");</jsp:scriptlet>`},
		{"aspx eval request", "body.raw", `<% eval(Request["cmd"]) %>`},
		{"aspx process with request form", "body.raw", `<% System.Diagnostics.Process.Start(Request.Form["cmd"]); %>`},
		{"aspx process with querystring", "body.raw", `<% System.Diagnostics.Process.Start("cmd.exe", Request.QueryString["a"]); %>`},
		{"webshell control interface", "uri", `/uploads/shell.php?action=exec&cmd=whoami`},
		{"c99 control interface", "uri", `/files/c99.php?act=cmd&cmd=id`},
	}

	for _, tc := range shells {
		t.Run(tc.name, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: tc.source}, text: tc.text}
			if _, ok := analyzeWebshell(candidate); !ok {
				t.Fatalf("analyzeWebshell missed a real webshell: %q", tc.text)
			}
		})
	}
}

// TestWebshellControlInterfaceIsSurfaceScoped pins both directions of the
// surface scoping on the control-interface branch. The FP and the attack are
// byte-identical strings, so the surface is the only thing that can separate them.
func TestWebshellControlInterfaceIsSurfaceScoped(t *testing.T) {
	const controlURL = "/data/manage/cmd.php?cmd=id"

	t.Run("fires on request target", func(t *testing.T) {
		for _, source := range []string{"uri", "query"} {
			candidate := semanticCandidate{input: InputPoint{Source: source}, text: controlURL}
			if _, ok := analyzeWebshell(candidate); !ok {
				t.Errorf("analyzeWebshell missed a control interface on the %q surface", source)
			}
		}
	})

	t.Run("does not fire on quoted document", func(t *testing.T) {
		advisory := "# NetMizer 日志管理系统 cmd.php 远程命令执行漏洞\n## 漏洞描述\n" +
			"攻击者通过传入 cmd 参数即可命令执行\n## 漏洞复现\n```\n" + controlURL + "\n```\n"
		for _, source := range []string{"body.raw", "body.form", "header", "cookie"} {
			candidate := semanticCandidate{input: InputPoint{Source: source}, text: advisory}
			if _, ok := analyzeWebshell(candidate); ok {
				t.Errorf("analyzeWebshell flagged an advisory quoting a PoC URL on the %q surface", source)
			}
		}
	})
}

// TestWebshellDetectCoversCrossSurfaceControlRequest pins the case the surface
// scoping must not cost: the shell path arrives in the request target while the
// command parameter arrives in the body.
func TestWebshellDetectCoversCrossSurfaceControlRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://x/uploads/shell.php", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqCtx := &engine.RequestContext{
		Request:     req,
		DecodedBody: []byte("action=exec&cmd=whoami"),
		Metadata:    map[string]any{},
	}

	got, err := NewWebshellDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected {
		t.Fatal("WebshellDetector.Detect missed a control request whose path and parameter split across surfaces")
	}
}

// TestWebshellDetectIgnoresShellPathQuotedInBody is the other half: the same
// detector must not claim a control interface was accessed when the PoC URL only
// appears inside a posted document.
func TestWebshellDetectIgnoresShellPathQuotedInBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://x/api/articles", nil)
	req.Header.Set("Content-Type", "text/markdown")
	reqCtx := &engine.RequestContext{
		Request:     req,
		DecodedBody: []byte("## 漏洞复现\n```\n/uploads/shell.php?action=exec&cmd=whoami\n```\n"),
		Metadata:    map[string]any{},
	}

	got, err := NewWebshellDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("WebshellDetector.Detect flagged a posted advisory as a control interface: %s", got.Message)
	}
}
