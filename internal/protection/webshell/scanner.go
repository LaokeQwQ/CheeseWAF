package webshell

import (
	"bytes"
	"regexp"
	"strings"
)

type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Scanner struct {
	rules []rule
}

type rule struct {
	id       string
	severity string
	message  string
	pattern  *regexp.Regexp
}

func NewScanner() *Scanner {
	return &Scanner{rules: []rule{
		{id: "php-eval", severity: "critical", message: "PHP dynamic code execution", pattern: regexp.MustCompile(`(?i)\b(eval|assert|preg_replace)\s*\(`)},
		{id: "php-shell-exec", severity: "critical", message: "Shell command execution", pattern: regexp.MustCompile(`(?i)\b(shell_exec|system|passthru|popen|proc_open)\s*\(`)},
		{id: "jsp-runtime-exec", severity: "critical", message: "JSP runtime command execution", pattern: regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\s*\(`)},
		{id: "asp-execute", severity: "high", message: "ASP dynamic execution", pattern: regexp.MustCompile(`(?i)\b(execute|eval|wscript\.shell)\b`)},
		{id: "encoded-payload", severity: "medium", message: "Large encoded payload", pattern: regexp.MustCompile(`(?i)(base64_decode|fromCharCode|atob)\s*\(`)},
	}}
}

func (s *Scanner) Scan(name string, content []byte) []Finding {
	if s == nil {
		s = NewScanner()
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	text := string(content)
	var findings []Finding
	for _, rule := range s.rules {
		if rule.pattern.MatchString(text) {
			findings = append(findings, Finding{Rule: rule.id, Severity: rule.severity, Message: rule.message})
		}
	}
	if strings.HasSuffix(strings.ToLower(name), ".php") && bytes.Contains(bytes.ToLower(content), []byte("$_post")) && bytes.Contains(bytes.ToLower(content), []byte("base64_decode")) {
		findings = append(findings, Finding{Rule: "php-post-loader", Severity: "high", Message: "POST controlled PHP loader"})
	}
	return findings
}
