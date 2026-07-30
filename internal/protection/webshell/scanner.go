package webshell

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"
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
		{id: "php-eval", severity: "critical", message: "PHP dynamic code execution", pattern: regexp.MustCompile(`(?i)\b(eval|assert|create_function)\s*\(`)},
		{id: "php-shell-exec", severity: "critical", message: "Shell command execution", pattern: regexp.MustCompile(`(?i)\b(shell_exec|system|passthru|popen|proc_open|exec|pcntl_exec)\s*\(`)},
		{id: "php-preg-e", severity: "critical", message: "preg_replace with /e modifier", pattern: regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]*/[imsxADSUXJu]*e`)},
		{id: "php-variable-function", severity: "high", message: "Variable function call pattern", pattern: regexp.MustCompile(`(?i)\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`)},
		{id: "php-file-include", severity: "high", message: "Dynamic include/require", pattern: regexp.MustCompile(`(?i)\b(include|require|include_once|require_once)\s*\(?\s*\$`)},
		{id: "php-obfuscation", severity: "high", message: "Common PHP obfuscation helpers", pattern: regexp.MustCompile(`(?i)\b(str_rot13|gzinflate|gzuncompress|gzdecode|strrev|rawurldecode)\s*\(`)},
		{id: "jsp-runtime-exec", severity: "critical", message: "JSP runtime command execution", pattern: regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\s*\(`)},
		{id: "asp-execute", severity: "high", message: "ASP dynamic execution", pattern: regexp.MustCompile(`(?i)\b(execute|eval|wscript\.shell|server\.createobject)\b`)},
		{id: "encoded-payload", severity: "medium", message: "Large encoded payload", pattern: regexp.MustCompile(`(?i)(base64_decode|fromCharCode|atob)\s*\(`)},
		{id: "php-assert-string", severity: "critical", message: "assert with string payload", pattern: regexp.MustCompile(`(?i)\bassert\s*\(\s*['"$]`)},
	}}
}

func (s *Scanner) Scan(name string, content []byte) []Finding {
	if s == nil {
		s = NewScanner()
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	// Normalize before matching so comments cannot hide dangerous calls.
	normalized := normalizeShellSource(string(content), name)
	var findings []Finding
	seen := map[string]struct{}{}
	for _, rule := range s.rules {
		if rule.pattern.MatchString(normalized) {
			if _, ok := seen[rule.id]; ok {
				continue
			}
			seen[rule.id] = struct{}{}
			findings = append(findings, Finding{Rule: rule.id, Severity: rule.severity, Message: rule.message})
		}
	}
	lowerName := strings.ToLower(name)
	lowerNorm := strings.ToLower(normalized)
	if strings.HasSuffix(lowerName, ".php") || strings.Contains(lowerNorm, "<?php") {
		if strings.Contains(lowerNorm, "$_post") && strings.Contains(lowerNorm, "base64_decode") {
			findings = append(findings, Finding{Rule: "php-post-loader", Severity: "high", Message: "POST controlled PHP loader"})
		}
		if highEntropySuspicious(normalized) {
			findings = append(findings, Finding{Rule: "php-high-entropy", Severity: "medium", Message: "High-entropy payload typical of obfuscated webshells"})
		}
	}
	return findings
}

// normalizeShellSource strips PHP comments and collapses whitespace for rule matching.
func normalizeShellSource(src, name string) string {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".php") || strings.Contains(strings.ToLower(src), "<?php") || strings.Contains(src, "<?=") {
		src = stripPHPComments(src)
	}
	// Collapse runs of whitespace so split call sites still match.
	var b strings.Builder
	b.Grow(len(src))
	prevSpace := false
	for _, r := range src {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

func stripPHPComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	i := 0
	inSingle, inDouble, inHeredoc := false, false, false
	for i < len(src) {
		// Block comments /* */
		if !inSingle && !inDouble && !inHeredoc && i+1 < len(src) && src[i] == '/' && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			if i+1 < len(src) {
				i += 2
			}
			out.WriteByte(' ')
			continue
		}
		// Line comments // or #
		if !inSingle && !inDouble && !inHeredoc && ((i+1 < len(src) && src[i] == '/' && src[i+1] == '/') || src[i] == '#') {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			out.WriteByte(' ')
			continue
		}
		c := src[i]
		if c == '\'' && !inDouble && !inHeredoc {
			inSingle = !inSingle
		} else if c == '"' && !inSingle && !inHeredoc {
			inDouble = !inDouble
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

func highEntropySuspicious(src string) bool {
	// Look for long base64-like blobs often used by one-liner webshells.
	re := regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
	return re.MatchString(src)
}
