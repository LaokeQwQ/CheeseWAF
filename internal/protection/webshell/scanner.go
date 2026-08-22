package webshell

import (
	"bytes"
	"context"
	"encoding/base64"
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

const (
	maxScanBytes       = 1 << 20
	maxDecodedVariants = 16
	maxBase64Tokens    = 32
	maxURLDecodeLayers = 3
)

func NewScanner() *Scanner {
	return &Scanner{rules: []rule{
		{id: "php-eval", severity: "critical", message: "PHP dynamic code execution", pattern: regexp.MustCompile(`(?i)\b(eval|assert|create_function)\s*\(`)},
		{id: "php-shell-exec", severity: "critical", message: "Shell command execution", pattern: regexp.MustCompile(`(?i)\b(shell_exec|system|passthru|popen|proc_open|exec|pcntl_exec)\s*\(`)},
		{id: "php-preg-e", severity: "critical", message: "preg_replace with /e modifier", pattern: regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]*/[imsxADSUXJu]*e`)},
		{id: "php-variable-function", severity: "high", message: "Variable function call pattern", pattern: regexp.MustCompile(`(?i)(?:\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|call_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE))`)},
		{id: "php-file-include", severity: "high", message: "Dynamic include/require", pattern: regexp.MustCompile(`(?i)\b(include|require|include_once|require_once)\s*\(?\s*\$`)},
		{id: "php-obfuscation", severity: "high", message: "Common PHP obfuscation helpers", pattern: regexp.MustCompile(`(?i)\b(str_rot13|gzinflate|gzuncompress|gzdecode|strrev|rawurldecode)\s*\(`)},
		{id: "jsp-runtime-exec", severity: "critical", message: "JSP runtime command execution", pattern: regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\s*\(`)},
		{id: "asp-execute", severity: "high", message: "ASP dynamic execution", pattern: regexp.MustCompile(`(?i)\b(execute|eval|wscript\.shell|server\.createobject)\b`)},
		{id: "encoded-payload", severity: "medium", message: "Large encoded payload", pattern: regexp.MustCompile(`(?i)(base64_decode|fromCharCode|atob)\s*\(`)},
		{id: "php-assert-string", severity: "critical", message: "assert with string payload", pattern: regexp.MustCompile(`(?i)\bassert\s*\(\s*['"$]`)},
	}}
}

func (s *Scanner) Scan(name string, content []byte) []Finding {
	findings, _ := s.ScanContext(context.Background(), name, content)
	return findings
}

func (s *Scanner) ScanContext(ctx context.Context, name string, content []byte) ([]Finding, error) {
	if s == nil {
		s = NewScanner()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(content) > maxScanBytes {
		content = content[:maxScanBytes]
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	variants, err := decodedSourceVariants(ctx, string(content))
	if err != nil {
		return nil, err
	}
	var findings []Finding
	seen := map[string]struct{}{}
	for _, source := range variants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Normalize before matching so comments cannot hide dangerous calls.
		normalized := normalizeShellSource(source, name)
		for _, rule := range s.rules {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if rule.pattern.MatchString(normalized) && ruleApplies(rule.id, name, normalized) {
				if _, ok := seen[rule.id]; ok {
					continue
				}
				seen[rule.id] = struct{}{}
				findings = append(findings, Finding{Rule: rule.id, Severity: rule.severity, Message: rule.message})
			}
		}
		lowerName := strings.ToLower(name)
		lowerNorm := strings.ToLower(normalized)
		if isPHPSource(lowerName, lowerNorm) {
			if hasConcatenatedVariableExecution(normalized) {
				if _, ok := seen["php-variable-function"]; !ok {
					seen["php-variable-function"] = struct{}{}
					findings = append(findings, Finding{Rule: "php-variable-function", Severity: "high", Message: "Variable function call pattern"})
				}
			}
			if hasPHPExecutionAndInput(lowerNorm) && strings.Contains(lowerNorm, "base64_decode") {
				if _, ok := seen["php-post-loader"]; !ok {
					seen["php-post-loader"] = struct{}{}
					findings = append(findings, Finding{Rule: "php-post-loader", Severity: "high", Message: "POST controlled PHP loader"})
				}
			}
			if hasPHPExecutionAndInput(lowerNorm) && highEntropySuspicious(normalized) {
				if _, ok := seen["php-high-entropy"]; !ok {
					seen["php-high-entropy"] = struct{}{}
					findings = append(findings, Finding{Rule: "php-high-entropy", Severity: "medium", Message: "High-entropy payload typical of obfuscated webshells"})
				}
			}
		}
	}
	return findings, nil
}

func ruleApplies(id, name, normalized string) bool {
	lowerName := strings.ToLower(name)
	lower := strings.ToLower(normalized)
	switch id {
	case "php-eval", "php-shell-exec", "php-preg-e", "php-variable-function", "php-file-include", "php-assert-string":
		return isPHPSource(lowerName, lower)
	case "php-obfuscation", "encoded-payload":
		return isPHPSource(lowerName, lower) && hasPHPExecutionAndInput(lower)
	case "jsp-runtime-exec":
		return (hasSuffixFold(lowerName, ".jsp", ".jspx") || strings.Contains(lower, "<%") || strings.Contains(lower, "<jsp:")) &&
			(strings.Contains(lower, "request.getparameter") || strings.Contains(lower, "${param."))
	case "asp-execute":
		return (hasSuffixFold(lowerName, ".asp", ".aspx") || strings.Contains(lower, "<%") || strings.Contains(lower, "runat=\"server\"")) &&
			strings.Contains(lower, "request")
	default:
		return true
	}
}

func isPHPSource(lowerName, lowerSource string) bool {
	return hasSuffixFold(lowerName, ".php", ".php3", ".php4", ".php5", ".phtml", ".phar") ||
		phpOpenTagPattern.MatchString(lowerSource)
}

func hasSuffixFold(lower string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func hasPHPExecutionAndInput(lower string) bool {
	return phpExecutionPattern.MatchString(lower) && phpExternalInputPattern.MatchString(lower)
}

func hasConcatenatedVariableExecution(source string) bool {
	if !phpExternalInputPattern.MatchString(source) {
		return false
	}
	for _, match := range phpStringAssignmentPattern.FindAllStringSubmatch(source, 16) {
		if len(match) != 3 {
			continue
		}
		functionName := strings.NewReplacer("'", "", `"`, "", ".", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(match[2])
		if _, dangerous := dangerousPHPFunctions[strings.ToLower(functionName)]; !dangerous {
			continue
		}
		invocation := regexp.MustCompile(`(?i)\$` + regexp.QuoteMeta(match[1]) + `\s*\(`)
		if invocation.MatchString(source) {
			return true
		}
	}
	for _, match := range phpExternalVariableAssignmentPattern.FindAllStringSubmatch(source, 16) {
		if len(match) != 2 {
			continue
		}
		invocation := regexp.MustCompile(`(?i)\$` + regexp.QuoteMeta(match[1]) + `\s*\(`)
		if invocation.MatchString(source) {
			return true
		}
	}
	return false
}

func decodedSourceVariants(ctx context.Context, source string) ([]string, error) {
	if len(source) > maxScanBytes {
		source = source[:maxScanBytes]
	}
	variants := []string{source}
	seen := map[string]struct{}{source: {}}
	current := source
	for layer := 0; layer < maxURLDecodeLayers && len(variants) < maxDecodedVariants; layer++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		decoded, changed := decodePercentLayer(current)
		if !changed || len(decoded) > maxScanBytes {
			break
		}
		if _, exists := seen[decoded]; exists {
			break
		}
		seen[decoded] = struct{}{}
		variants = append(variants, decoded)
		current = decoded
	}
	urlVariants := append([]string(nil), variants...)
	for _, variant := range urlVariants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, token := range base64Tokens(variant) {
			if len(variants) >= maxDecodedVariants {
				return variants, nil
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			decoded, ok := decodeBase64Token(token)
			if !ok || !mostlyText(decoded) || !looksLikeExecutableSource(decoded) {
				continue
			}
			text := string(decoded)
			if _, exists := seen[text]; exists {
				continue
			}
			seen[text] = struct{}{}
			variants = append(variants, text)
		}
	}
	return variants, nil
}

var base64TokenPattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

func base64Tokens(source string) []string {
	return base64TokenPattern.FindAllString(source, maxBase64Tokens)
}

func decodePercentLayer(source string) (string, bool) {
	decoded := make([]byte, 0, len(source))
	changed := false
	for index := 0; index < len(source); index++ {
		if source[index] == '%' && index+2 < len(source) {
			high, highOK := hexNibble(source[index+1])
			low, lowOK := hexNibble(source[index+2])
			if highOK && lowOK {
				decoded = append(decoded, high<<4|low)
				index += 2
				changed = true
				continue
			}
		}
		decoded = append(decoded, source[index])
	}
	return string(decoded), changed
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func mostlyText(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	printable := 0
	for _, char := range value {
		if char == '\n' || char == '\r' || char == '\t' || char >= 0x20 && char < 0x7f {
			printable++
		}
	}
	return printable*10 >= len(value)*9
}

func looksLikeExecutableSource(value []byte) bool {
	lower := bytes.ToLower(value)
	for _, marker := range [][]byte{
		[]byte("<?php"), []byte("<?="), []byte("$_get["), []byte("$_post["),
		[]byte("$_request["), []byte("$_cookie["), []byte("<jsp:"), []byte("runtime.getruntime"),
		[]byte("runat=\"server\""), []byte("<%"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func decodeBase64Token(token string) ([]byte, bool) {
	if len(token) > maxScanBytes*2 {
		return nil, false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(token)
		if err == nil && len(decoded) > 0 && len(decoded) <= maxScanBytes {
			return decoded, true
		}
	}
	return nil, false
}

// normalizeShellSource strips PHP comments and collapses whitespace for rule matching.
func normalizeShellSource(src, name string) string {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".php") || phpOpenTagPattern.MatchString(strings.ToLower(src)) {
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
	return highEntropyPattern.MatchString(src)
}

var (
	phpExecutionPattern                  = regexp.MustCompile(`(?i)\b(?:eval|assert|system|shell_exec|passthru|exec|proc_open|popen|create_function)\s*\(`)
	phpExternalInputPattern              = regexp.MustCompile(`(?i)\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`)
	phpExternalVariableAssignmentPattern = regexp.MustCompile(`(?i)\$([a-z_][a-z0-9_]*)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`)
	phpStringAssignmentPattern           = regexp.MustCompile(`(?i)\$([a-z_][a-z0-9_]*)\s*=\s*((?:['"][a-z_]+['"]\s*\.?\s*)+)\s*;`)
	phpOpenTagPattern                    = regexp.MustCompile(`(?i)<\?(?:php\b|=|\s)`)
	highEntropyPattern                   = regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
	dangerousPHPFunctions                = map[string]struct{}{
		"assert": {}, "create_function": {}, "eval": {}, "exec": {}, "passthru": {}, "popen": {}, "proc_open": {}, "shell_exec": {}, "system": {},
	}
)
