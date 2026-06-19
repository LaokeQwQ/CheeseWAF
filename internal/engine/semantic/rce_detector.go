package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var rcePatterns = []*regexp.Regexp{
	// Shell operators + commands
	regexp.MustCompile(`(?i)(?:;|&&|\|\||\||\n)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat|telnet|tftp|dig|nslookup|host|arp|ifconfig|lua|gawk|awk|sed|tr)\b`),
	// Command substitution
	regexp.MustCompile(`(?i)(?:\$\(|` + "`" + `)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat|telnet)\b`),
	// Shell binaries
	regexp.MustCompile(`(?i)(?:/bin/(?:sh|bash|dash|zsh|ksh|tcsh|csh)|cmd\.exe|powershell\.exe|pwsh\.exe)`),
	// Download + execute chain
	regexp.MustCompile(`(?i)(?:curl|wget|fetch|lynx)\s+[^|;&\n]+(?:\||;|&&|\n)\s*(?:sh|bash|zsh|dash|ksh|python3?|php|perl|ruby|node|nc)`),
	// Shell -c invocation
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:bash|sh|zsh|dash|ksh|tcsh|csh)\s+-c\b`),
	// Windows CMD
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])cmd(?:\.exe)?\s*/c\s+(?:whoami|id|dir|type|powershell|certutil|curl|wget|ping|nslookup|net\s+user|net\s+localgroup|reg\s+query|sc\s+query|tasklist|wmic)\b`),
	// PowerShell encoded/obfuscated
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,160}\s-(?:e|en|enc|encodedcommand|ec|encoded|enco)\s+[a-z0-9+/=]{12,}`),
	// PowerShell dynamic execution
	regexp.MustCompile(`(?i)\b(?:iex|invoke-expression|invoke-command|start-process|new-object|\.invoke\s*\(|\.ps1\b)\b[^\r\n]{0,200}\b(?:downloadstring|new-object|net\.webclient|frombase64string|wmi|comobject|microsoft\.win32)\b`),
	// Inline interpreter invocation
	regexp.MustCompile(`(?i)(?:python3?|perl|php|ruby|node|lua)\s+(?:-c|-e|-r|-S)\b`),
	// Binary aliases for dangerous operations
	regexp.MustCompile(`(?i)(?:^|[=&\s])(?:/usr)?/bin/(?:perl|python3?|php|ruby|node|gunzip|unxz|ab|ansible|chef|cscli|visudo|gpgsm|ssh-keyscan|nmap|expect|scp|rsync|sendmail)\b`),
	// File read of sensitive paths via command
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:cat|head|tail|less|more|type|xxd|hexdump|od)(?:\s|\$\{?ifs\}?)+(?:/etc/(?:passwd|shadow|hosts|group|sudoers|crontab)|/proc/(?:self|version|cpuinfo|loadavg)|/var/(?:log|run|www)|/root/|/home/)`),
	// Shell variable expansion for command
	regexp.MustCompile(`(?i)(?:\$SHELL|\$\{SHELL\})\s+-c\b`),
	// Reverse shell patterns — /dev/tcp
	regexp.MustCompile(`(?i)(?:bash|sh|zsh|dash)\s+(?:-i|--login)?\s*(?:<|>|>>|<<<|<>|&>\s*)?/dev/tcp/`),
	// Common reverse shell one-liner patterns
	regexp.MustCompile(`(?i)(?:nc|ncat|netcat)\s+(?:-e\s+|--exec\s+)(?:/bin/(?:sh|bash)|cmd\.exe|powershell)`),
	regexp.MustCompile(`(?i)(?:python|perl|ruby|php)\s+-[er]\s+.+(?:socket|subprocess|system|exec|fsockopen|popen)`),
	// ${IFS} whitespace evasion
	regexp.MustCompile(`(?i)\$\{?ifs\}?(?:\s*\(?\s*(?:cat|id|whoami|ls|dir|curl|wget|bash|sh)\b)`),
	// File descriptor manipulation
	regexp.MustCompile(`(?i)(?:>&\s*(?:[0-9]|/dev|/proc)|(?:[0-9]|/dev/(?:tcp|udp))\s*>\s*(?:[0-9]|&))`),
	// Shell arithmetic expansion obfuscation (attacker psychology: bypass simple string matching)
	// $((69+52)) evaluates to a char code, used to construct command names dynamically
	regexp.MustCompile(`(?i)(?:\$\(\s*\(\s*\d+\s*[\+\-\*/%]\s*\d+\s*\)\s*\))`),
	// Backtick / $() with arithmetic and common probes
	regexp.MustCompile(`(?i)(?:\x60|[\\$]\().*(?:\d+\s*[\+\-\*/%]\s*\d+|id|whoami|ls|pwd|cat|curl|wget|uname|hostname|ifconfig|ipconfig)`),
	// Advanced PowerShell obfuscation techniques
	regexp.MustCompile(`(?i)(?:\b(?:powershell|pwsh)\b[^\r\n]{0,160}(?:-no(?:p|profile|-logo|-exit)|-w(?:in)?\s*(?:hidden|0)|-window\s*(?:hidden|style)|-noni|-noninteractive|-noprofile))`),
	regexp.MustCompile(`(?i)(?:\b(?:powershell|pwsh)\b[^\r\n]{0,200}(?:\]\s*\+\s*\[|Join\(|\.Replace\(|\.ToChar|FromBase64CharArray|\[Convert\]::))`),
	// Variable-based obfuscation (attacker trick: splitting commands across variables)
	regexp.MustCompile(`(?i)(?:[&\|;\n]|%0[adAD]|%3[abB])(?:[a-z_][a-z0-9_]*=[a-z0-9_]+[\s;&|]+)*[a-z_][a-z0-9_]*\s*=\s*['"]?(?:cat|curl|wget|bash|sh|id|whoami|ls|dir)['"]?`),
	// Chained encoding/phases (attacker psychology: multi-layer obfuscation)
	regexp.MustCompile(`(?i)(?:(?:frombase64|base64_decode|atob)\s*\(.*(?:downloadstring|shell_exec|system|exec|passthru|popen)|downloadstring.*frombase64|eval.*base64_decode)`),
}

type RCEDetector struct {
	mode string
}

func NewRCEDetector(mode string) *RCEDetector {
	if mode == "" {
		mode = "block"
	}
	return &RCEDetector{mode: mode}
}

func (d *RCEDetector) ID() string    { return "semantic.rce" }
func (d *RCEDetector) Name() string  { return "Command Injection Semantic Detector" }
func (d *RCEDetector) Priority() int { return 320 }

func (d *RCEDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		for _, pattern := range rcePatterns {
			if pattern.MatchString(trimmed) {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "rce",
					Severity:   engine.SeverityCritical,
					Action:     actionForMode(d.mode),
					Message:    "command injection pattern matched",
					Confidence: 0.84,
					Payload:    trimmed,
				}, nil
			}
		}
	}
	return nil, nil
}
