package webshell

import "testing"

func TestScannerFindsPHPShellExecution(t *testing.T) {
	findings := NewScanner().Scan("upload.php", []byte(`<?php system($_GET["cmd"]); ?>`))
	if len(findings) == 0 || findings[0].Severity != "critical" {
		t.Fatalf("expected critical finding, got %+v", findings)
	}
}

func TestScannerDetectsCommentedPHPShell(t *testing.T) {
	// Comment between open tag and dangerous call must not hide the shell.
	payload := []byte(`<?php /* normal comment */ @eval(base64_decode($_POST['x'])); ?>`)
	findings := NewScanner().Scan("shell.php", payload)
	if len(findings) == 0 {
		t.Fatal("expected findings for commented PHP webshell")
	}
	foundEval := false
	for _, f := range findings {
		if f.Rule == "php-eval" || f.Rule == "php-post-loader" {
			foundEval = true
		}
	}
	if !foundEval {
		t.Fatalf("expected php-eval or php-post-loader, got %+v", findings)
	}
}
