package webshell

import "testing"

func TestScannerFindsPHPShellExecution(t *testing.T) {
	findings := NewScanner().Scan("upload.php", []byte(`<?php system($_GET["cmd"]); ?>`))
	if len(findings) == 0 || findings[0].Severity != "critical" {
		t.Fatalf("expected critical finding, got %+v", findings)
	}
}
