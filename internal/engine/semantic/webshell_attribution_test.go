package semantic

import "testing"

// TestWebshellRejectsSecurityDocuments pins that analyzeWebshell honours the
// shared securityDocumentContext guard. Every other category that shares its
// grammar with security prose already routes through that guard; the webshell
// path did not, which put a structured POC writeup into the mined_probe FP set
// via the ASPX branch ("syntax: ASP.NET process or dynamic evaluation
// primitive"). A vulnerability disclosure that quotes a primitive is not a
// request that executes one.
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
			name: "wooyun disclosure quoting php primitive",
			text: "## 漏洞概要\n缺陷编号：wooyun-2015-0123456\n漏洞标题：某站存在文件上传导致命令执行\n" +
				"相关厂商：某公司\n漏洞作者：白帽子\n提交时间：2015-01-01\n公开时间：2015-03-01\n" +
				"漏洞类型：文件上传导致任意代码执行\n危害等级：高\n\n" +
				"## 详细说明\n上传点未校验扩展名，可写入 <?php eval($_POST['cmd']); ?> 从而获得 webshell。\n" +
				"## 修复方案\n服务端白名单校验扩展名，并将上传目录设为不可执行。\n",
		},
	}

	for _, tc := range docs {
		t.Run(tc.name, func(t *testing.T) {
			if !securityDocumentContext(tc.text) {
				t.Fatalf("precondition failed: securityDocumentContext should classify this as a document")
			}
			if _, ok := analyzeWebshell(semanticCandidate{text: tc.text}); ok {
				t.Fatalf("analyzeWebshell flagged a security document as a webshell")
			}
		})
	}
}

// TestWebshellStillDetectsRealShells guards the revert direction: the document
// guard and the ASPX input-reachability requirement must not cost real
// detections. Each payload is an actual shell body or control request.
func TestWebshellStillDetectsRealShells(t *testing.T) {
	shells := []struct {
		name string
		text string
	}{
		{"php eval post", `<?php eval($_POST['cmd']); ?>`},
		{"php system get", `<?php system($_GET['c']); ?>`},
		{"php shortopen assert request", `<?= assert($_REQUEST['x']); ?>`},
		{"php base64 obfuscated cookie", `<?php eval(base64_decode($_COOKIE['p'])); ?>`},
		{"jsp runtime getparameter", `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`},
		{"jsp processbuilder param", `<% new ProcessBuilder(request.getParameter("c")).start(); %>`},
		{"aspx eval request", `<% eval(Request["cmd"]) %>`},
		{"aspx process with request form", `<% System.Diagnostics.Process.Start(Request.Form["cmd"]); %>`},
		{"aspx process with querystring", `<% System.Diagnostics.Process.Start("cmd.exe", Request.QueryString["a"]); %>`},
		{"webshell control interface", `/uploads/shell.php?action=exec&cmd=whoami`},
		{"c99 control interface", `/files/c99.php?act=cmd&cmd=id`},
	}

	for _, tc := range shells {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := analyzeWebshell(semanticCandidate{text: tc.text}); !ok {
				t.Fatalf("analyzeWebshell missed a real webshell: %q", tc.text)
			}
		})
	}
}
