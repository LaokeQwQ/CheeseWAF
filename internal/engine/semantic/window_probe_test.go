package semantic

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestWindowProbeGuardBehaviour is a throwaway diagnostic: for a handful of the
// benign documents that regressed after evidence-window localisation, report
// whether securityDocumentContext fires on the full document, on the local
// evidence window, or neither. Used to choose between window-only and
// AND(full, window) gating.
func TestWindowProbeGuardBehaviour(t *testing.T) {
	if testing.Short() {
		t.Skip("diagnostic probe")
	}
	path := "testdata/cybersec_benign_clean.jsonl"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("corpus unavailable: %v", err)
	}
	defer f.Close()

	// Indices reported as FP in the 233-FP run.
	want := map[int]bool{
		2120: true, 2251: true, 2312: true, 2374: true, 2383: true,
		3393: true, 3398: true, 3412: true, 4053: true, 4141: true,
		4240: true, 4259: true, 4889: true, 5078: true, 5250: true,
	}

	sqlIndicators := []string{
		"xp_cmdshell", "exec master", "union select", "union all select",
		"into outfile", "load_file", "information_schema", "sleep(",
		"benchmark(", "waitfor delay", "pg_sleep", "1=1", "1=0",
		"' or", "\" or", "or 1=", "and 1=",
	}
	rceIndicators := []string{
		";cat ", "|cat ", "| cat ", ";id", "|id", "| id",
		"|bash", "| bash", "|sh ", "| sh ", "/bin/sh", "/bin/bash",
		"/etc/passwd", "/etc/shadow", "whoami", "nc ", "netcat",
		"wget ", "curl ", "<?php", "eval(", "system(", "passthru(",
		"shell_exec(", "proc_open(", "popen(", "exec(",
		"runtime.exec", "processbuilder", "() { :;};", "${jndi:",
	}
	lfiIndicators := []string{
		"../", "....//", `..\/`, ".htaccess",
		"/etc/passwd", "/etc/shadow", "/proc/self", "/root/",
		"php://", "phar://", "zip://", "expect://", "data://",
		".ssh/id_rsa", ".aws/credentials", ".git/config", ".env",
		"web-inf/web.xml", "boot.ini", "win.ini", "wp-config",
		"docker.sock", "/var/log/",
	}
	all := append(append(append([]string{}, sqlIndicators...), rceIndicators...), lfiIndicators...)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	idx := -1
	for sc.Scan() {
		idx++
		if !want[idx] {
			continue
		}
		var rec struct {
			Text    string `json:"text"`
			Payload string `json:"payload"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		text := rec.Text
		if text == "" {
			text = rec.Payload
		}
		if text == "" {
			text = rec.Content
		}
		if text == "" {
			continue
		}
		win := evidenceWindow(text, all)
		t.Logf("idx=%d len=%d full=%v win=%v winLen=%d techFull=%v techWin=%v head=%q",
			idx, len(text),
			securityDocumentContext(text), securityDocumentContext(win), len(win),
			technicalDocumentationContext(text), technicalDocumentationContext(win),
			truncateProbe(text, 60))
		t.Logf("   winText=%q", truncateProbe(win, 200))
	}
}

func truncateProbe(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= n {
		return s
	}
	return s[:n]
}
