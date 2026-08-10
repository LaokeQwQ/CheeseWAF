package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// WebshellDetector detects PHP/JSP/ASPX webshell upload and backdoor patterns.
//
// Core signatures:
//   - PHP one-liner: eval($_POST['x']) / system($_GET['cmd']) / assert($_REQUEST['c'])
//   - Obfuscated eval: base64_decode / gzinflate / str_rot13 / create_function
//   - JSP backdoor: Runtime.getRuntime().exec / ProcessBuilder
//   - ASPX backdoor: System.Diagnostics.Process.Start / eval(Request["cmd"])
//
// Gate: requires code-execution primitive + external-input variable in close proximity.
type WebshellDetector struct{ mode string }

func NewWebshellDetector(mode string) *WebshellDetector {
	return &WebshellDetector{mode: mode}
}

func (d *WebshellDetector) ID() string    { return "semantic.webshell" }
func (d *WebshellDetector) Name() string  { return "Webshell Backdoor Detector" }
func (d *WebshellDetector) Priority() int { return 350 }

func (d *WebshellDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	surface := requestText(reqCtx)
	if securityDocumentContext(surface) {
		return nil, nil
	}
	normalized := strings.ToLower(surface)

	// ---- PHP webshell signatures ----
	if strings.Contains(normalized, "<?php") || strings.Contains(normalized, "<?=") {
		if hasWebshellPrimitive(normalized) && hasExternalInput(normalized) {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "webshell",
				Severity:   engine.SeverityCritical,
				Action:     actionForMode(d.mode),
				Message:    "PHP webshell backdoor pattern detected",
				Confidence: 0.95,
				Payload:    truncateWebshell(surface, 200),
			}, nil
		}
	}

	// ---- JSP webshell signatures ----
	if strings.Contains(normalized, "runtime.getruntime()") || strings.Contains(normalized, "processbuilder") {
		if strings.Contains(normalized, "request.getparameter") || strings.Contains(normalized, "${param.") {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "webshell",
				Severity:   engine.SeverityCritical,
				Action:     actionForMode(d.mode),
				Message:    "JSP webshell backdoor pattern detected",
				Confidence: 0.93,
				Payload:    truncateWebshell(surface, 200),
			}, nil
		}
	}

	// ---- ASPX webshell signatures ----
	// Bare system.diagnostics.process additionally requires request-input
	// reachability; see analyzeWebshell for the rationale.
	if strings.Contains(normalized, "eval(request[") ||
		(strings.Contains(normalized, "system.diagnostics.process") && hasASPXRequestInput(normalized)) {
		return &engine.DetectionResult{
			Detected:   true,
			DetectorID: d.ID(),
			Category:   "webshell",
			Severity:   engine.SeverityCritical,
			Action:     actionForMode(d.mode),
			Message:    "ASPX webshell backdoor pattern detected",
			Confidence: 0.92,
			Payload:    truncateWebshell(surface, 200),
		}, nil
	}

	// ---- Generic webshell path signature ----
	// Common webshell filenames: shell.php / webshell.php / c99.php / r57.php / backdoor.php / cmd.php
	if rxWebshellPath.MatchString(normalized) {
		// Require action/cmd/exec parameter to reduce FP on legitimate files named "shell.php"
		if strings.Contains(normalized, "action=") || strings.Contains(normalized, "cmd=") || strings.Contains(normalized, "exec=") {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "webshell",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    "Webshell control interface accessed",
				Confidence: 0.88,
				Payload:    truncateWebshell(surface, 200),
			}, nil
		}
	}

	return nil, nil
}

// hasWebshellPrimitive checks for PHP code-execution functions.
func hasWebshellPrimitive(normalized string) bool {
	return rxPHPExec.MatchString(normalized) ||
		rxPHPObfuscate.MatchString(normalized)
}

// hasExternalInput checks for PHP superglobals ($_POST/$_GET/$_REQUEST/$_COOKIE).
func hasExternalInput(normalized string) bool {
	return rxPHPSuperglobal.MatchString(normalized)
}

// hasASPXRequestInput reports whether the text references ASP.NET request input
// (Request[...], Request.Form/QueryString/Cookies/Params/Item, or the classic
// VBScript Request(...) accessor). It is the ASP.NET analogue of
// hasExternalInput and supplies the reachability half of the ASPX branch.
func hasASPXRequestInput(normalized string) bool {
	return rxASPXRequestInput.MatchString(normalized)
}

// analyzeWebshell is the semantic analyzer entry point called from analyzer.go.
//
// Webshell grammar appears verbatim inside vulnerability disclosures, POC
// templates and CTF writeups, so this routes through the shared
// securityDocumentContext guard like every other prose-colliding category. A
// disclosure that quotes System.Diagnostics.Process is not a request that
// starts a process. See TestWebshellRejectsSecurityDocuments.
func analyzeWebshell(candidate semanticCandidate) (Hit, bool) {
	if securityDocumentContext(candidate.text) {
		return Hit{}, false
	}
	normalized := strings.ToLower(candidate.text)

	// PHP webshell: execution primitive + external input
	if (strings.Contains(normalized, "<?php") || strings.Contains(normalized, "<?=")) &&
		hasWebshellPrimitive(normalized) && hasExternalInput(normalized) {
		return hit(candidate, "webshell", engine.SeverityCritical, 0.95, map[string]bool{
			"syntax: PHP execution primitive with superglobal input":                  true,
			"semantics: attacker-controlled input reaches server-side code execution": true,
		}), true
	}

	// JSP webshell: Runtime.getRuntime() + request.getParameter
	if (strings.Contains(normalized, "runtime.getruntime()") || strings.Contains(normalized, "processbuilder")) &&
		(strings.Contains(normalized, "request.getparameter") || strings.Contains(normalized, "${param.")) {
		return hit(candidate, "webshell", engine.SeverityCritical, 0.93, map[string]bool{
			"syntax: Java process execution primitive with request parameter":            true,
			"semantics: attacker-controlled input reaches server-side process execution": true,
		}), true
	}

	// ASPX webshell: dynamic evaluation of request input, or process start whose
	// argument is request-controlled. eval(Request[ already carries the input
	// reachability in the token itself. A bare system.diagnostics.process does
	// not: it is the ordinary .NET way to start any process and shows up in
	// prose, stack traces and framework source, so it additionally requires a
	// request-input reference — matching the reachability requirement the PHP
	// branch above already enforces via hasExternalInput.
	if strings.Contains(normalized, "eval(request[") ||
		(strings.Contains(normalized, "system.diagnostics.process") && hasASPXRequestInput(normalized)) {
		return hit(candidate, "webshell", engine.SeverityCritical, 0.92, map[string]bool{
			"syntax: ASP.NET process or dynamic evaluation primitive":     true,
			"semantics: request input reaches server-side code execution": true,
		}), true
	}

	// Webshell control interface: known filename + action parameter
	if rxWebshellPath.MatchString(normalized) &&
		(strings.Contains(normalized, "action=") || strings.Contains(normalized, "cmd=") || strings.Contains(normalized, "exec=")) {
		return hit(candidate, "webshell", engine.SeverityHigh, 0.88, map[string]bool{
			"syntax: known webshell path with command parameter":     true,
			"semantics: remote command-control interface invocation": true,
		}), true
	}

	return Hit{}, false
}

var (
	// PHP execution primitives
	rxPHPExec = regexp.MustCompile(`(?:eval|system|shell_exec|passthru|exec|assert|proc_open|popen)\s*\(`)
	// PHP obfuscation layers
	rxPHPObfuscate = regexp.MustCompile(`(?:base64_decode|gzinflate|str_rot13|gzuncompress|create_function)\s*\(`)
	// PHP superglobals
	rxPHPSuperglobal = regexp.MustCompile(`(?i)\$_(?:post|get|request|cookie)\s*\[`)
	// ASP.NET request-input accessors (reachability half of the ASPX branch)
	rxASPXRequestInput = regexp.MustCompile(`(?i)request\s*(?:\[|\(|\.\s*(?:form|querystring|cookies|params|item|headers|inputstream)\b)`)
	// Common webshell filenames
	rxWebshellPath = regexp.MustCompile(`/(?:web)?shell\.php|/c(?:99|100)\.php|/r57\.php|/backdoor\.php|/cmd\.php|/[a-z0-9_-]*shell[a-z0-9_-]*\.(?:php|jsp|aspx)`)
)

func truncateWebshell(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
