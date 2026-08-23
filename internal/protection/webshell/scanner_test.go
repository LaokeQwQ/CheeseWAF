package webshell

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

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

func TestScannerDetectsPercentEncodedPHPShell(t *testing.T) {
	payload := []byte(`%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%20%3F%3E`)
	findings := NewScanner().Scan("upload.php", payload)
	if !hasFinding(findings, "php-shell-exec") {
		t.Fatalf("percent-encoded webshell was not detected: %+v", findings)
	}
}

func TestScannerDecodesValidEscapesAroundMalformedPercentInput(t *testing.T) {
	payload := []byte(`ignored=%zz&code=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%20%3F%3E`)
	findings := NewScanner().Scan("upload.php", payload)
	if !hasFinding(findings, "php-shell-exec") {
		t.Fatalf("malformed escape hid encoded webshell: %+v", findings)
	}
}

func TestScannerDetectsBase64EncodedPHPShell(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`<?php $_GET['fn']($_POST['arg']); ?>`))
	findings := NewScanner().Scan("payload.txt", []byte("data="+encoded))
	if !hasFinding(findings, "php-variable-function") {
		t.Fatalf("base64-encoded variable-function shell was not detected: %+v", findings)
	}
}

func TestScannerIgnoresDocumentationAndEntropyAlone(t *testing.T) {
	documentation := []byte(`Security review: eval($input), system($command), and base64_decode($payload) are prohibited.`)
	if findings := NewScanner().Scan("review.txt", documentation); len(findings) != 0 {
		t.Fatalf("documentation produced findings: %+v", findings)
	}
	legitimateBlob := []byte(`<?php $logo = '` + strings.Repeat("A", 160) + `'; echo $logo; ?>`)
	if findings := NewScanner().Scan("theme.php", legitimateBlob); len(findings) != 0 {
		t.Fatalf("entropy alone produced findings: %+v", findings)
	}
}

func TestScannerDetectsConcatenatedVariableFunction(t *testing.T) {
	payload := []byte(`<?php $fn = 'sys'.'tem'; $arg = $_GET['cmd']; $fn($arg); ?>`)
	findings := NewScanner().Scan("upload.php", payload)
	if !hasFinding(findings, "php-variable-function") {
		t.Fatalf("concatenated variable function was not detected: %+v", findings)
	}
}

func TestScannerDetectsCallUserFuncFromRequest(t *testing.T) {
	payload := []byte(`<?php call_user_func($_GET['fn'], $_POST['arg']); ?>`)
	findings := NewScanner().Scan("upload.php", payload)
	if !hasFinding(findings, "php-variable-function") {
		t.Fatalf("request-controlled call_user_func was not detected: %+v", findings)
	}
}

func TestScannerDetectsTaintedVariableFunction(t *testing.T) {
	payload := []byte(`<?php $fn = $_GET['fn']; $arg = $_POST['arg']; $fn($arg); ?>`)
	findings := NewScanner().Scan("upload.php", payload)
	if !hasFinding(findings, "php-variable-function") {
		t.Fatalf("tainted variable function was not detected: %+v", findings)
	}
}

func TestScannerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewScanner().ScanContext(ctx, "upload.php", []byte(`<?php system($_GET['cmd']); ?>`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanContext error = %v, want context.Canceled", err)
	}
}

func hasFinding(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}
