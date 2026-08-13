package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

const realPHPShellBody = `<?php @eval($_POST['cheese']); ?>`

// TestWebshellDocumentGuardIsNotAnEvasionOracle pins the property that broke when
// securityDocumentContext was bolted onto the webshell path: the guard reads the
// attacker's own text, so any prose marker the attacker prepends to a live shell
// bought total suppression. The guards key on prose *presence*, and their only
// defense is a 100-200 byte length floor an attacker pays in padding.
//
// Each prefix below satisfies one sub-guard of securityDocumentContext while the
// body remains an unmodified PHP shell.
func TestWebshellDocumentGuardIsNotAnEvasionOracle(t *testing.T) {
	prefixes := []struct {
		name   string
		prefix string
	}{
		{"structured poc template", "【漏洞类型】x\n【POC利用方法】\n" + strings.Repeat("a", 160)},
		{"ctf challenge writeup", "## Description\n" + strings.Repeat("c", 210)},
		{"python import stack", "import os\nimport sys\nimport re\nimport json\n" + strings.Repeat("z", 110)},
	}

	for _, tc := range prefixes {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.prefix + "\n" + realPHPShellBody

			if _, ok := analyzeWebshell(semanticCandidate{text: payload}); !ok {
				t.Errorf("analyzeWebshell missed a live PHP shell carrying a %s prefix; the document guard is an attacker-controllable suppression oracle", tc.name)
			}

			// End to end through the mounted analyzer: nothing may go undetected.
			req := httptest.NewRequest(http.MethodPost, "http://x/upload.php", nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqCtx := &engine.RequestContext{
				Request:     req,
				DecodedBody: []byte(payload),
				Metadata:    map[string]any{},
			}
			got, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected {
				t.Errorf("analyzer returned no detection at all for a live PHP shell with a %s prefix", tc.name)
			}
		})
	}
}

// TestWebshellDetectRequestSurfaceIsNotAnEvasionOracle covers the same hole on
// WebshellDetector.Detect, which gated on requestText — RequestURI plus
// User-Agent plus body. A padded User-Agent could disable the whole detector
// while the body stayed a pure shell.
func TestWebshellDetectRequestSurfaceIsNotAnEvasionOracle(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://x/upload.php", nil)
	req.Header.Set("User-Agent", "## Description "+strings.Repeat("c", 220))
	reqCtx := &engine.RequestContext{
		Request:     req,
		DecodedBody: []byte(realPHPShellBody),
		Metadata:    map[string]any{},
	}

	got, err := NewWebshellDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected {
		t.Fatalf("WebshellDetector.Detect missed a live PHP shell because a padded User-Agent tripped the document guard")
	}
}

// TestWebshellDetectsProcessStartWithoutRequestInput pins the class the ASPX
// reachability requirement wrongly excluded. For an uploaded .aspx body the file
// on disk IS the attack: Process.Start reached from a literal, a server control
// or a session value is still a shell. The PHP branch's hasExternalInput
// requirement does not transfer, because <?php + superglobal describes a
// request-driven shell while an uploaded ASPX page describes a planted one.
func TestWebshellDetectsProcessStartWithoutRequestInput(t *testing.T) {
	shells := []struct {
		name string
		text string
	}{
		{
			name: "literal argument process start",
			text: `<% System.Diagnostics.Process.Start("cmd.exe","/c net user cheese P@ss /add"); %>`,
		},
		{
			name: "processstartinfo with import namespace",
			text: `<%@ Import Namespace="System.Diagnostics" %><% var si=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c whoami"); si.UseShellExecute=false; System.Diagnostics.Process.Start(si); %>`,
		},
		{
			name: "webforms server control shell",
			text: `<%@ Page Language="C#" %><script runat="server">void Btn_Click(object s, EventArgs e){var p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+txtArg.Text;p.Start();}</script>`,
		},
	}

	for _, tc := range shells {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := analyzeWebshell(semanticCandidate{text: tc.text})
			if !ok {
				t.Fatalf("analyzeWebshell missed a real ASPX shell: %q", tc.text)
			}
			if hit.Category != "webshell" {
				t.Fatalf("category = %q, want webshell", hit.Category)
			}
		})
	}
}
