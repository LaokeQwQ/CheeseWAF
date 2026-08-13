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
	normalized := strings.ToLower(surface)
	target := ""
	if reqCtx != nil && reqCtx.Request != nil && reqCtx.Request.URL != nil {
		target = strings.ToLower(reqCtx.Request.URL.RequestURI())
	}

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
	// Bare system.diagnostics.process additionally requires an ASP.NET
	// server-side code delimiter; see analyzeWebshell for the rationale.
	if strings.Contains(normalized, "eval(request[") ||
		(strings.Contains(normalized, "system.diagnostics.process") && aspxServerCodeContext(normalized)) {
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
	//
	// The filename must appear in the request target, not anywhere in the request.
	// A security advisory POSTed as a body quotes PoC URLs verbatim, so matching the
	// body here claims "control interface accessed" about a request that never
	// touched one. The parameter is still read from the whole surface, which keeps
	// POST /shell.php with cmd=whoami in the body covered.
	if rxWebshellPath.MatchString(target) {
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

// aspxServerCodeContext reports whether the text carries an ASP.NET server-side
// code delimiter: an inline block (<% ... %>, covering the <%@ directive and
// <%= output forms) or a WebForms server script block (<script runat="server">).
//
// This is the ASPX analogue of the <?php / <?= requirement the PHP branch
// enforces, and it is a requirement to fire rather than a licence to suppress:
// prose quoting a .NET primitive in a sentence carries no delimiter, while a
// shell that drops the delimiter no longer executes.
// requestTargetSurface reports whether a candidate's input source carries the
// request target — the path or the query string. Sources named here must stay in
// sync with the collectors in analyzer.go.
func requestTargetSurface(source string) bool {
	return source == "uri" || source == "query"
}

// jspServerCodeContext reports whether the text carries a JSP server-side
// construct: a scriptlet or directive (<% ... %>, <%@, <%=), a jsp: action tag
// (including the <jsp:scriptlet> form used by .jspx), or an EL expression, which
// is the only way ${param.…} can reach anything.
//
// Same shape as the PHP <?php requirement: prose that quotes a Java primitive
// carries no delimiter, and a shell that drops the delimiter stops executing.
func jspServerCodeContext(normalized string) bool {
	return strings.Contains(normalized, "<%") ||
		strings.Contains(normalized, "<jsp:") ||
		strings.Contains(normalized, "${")
}

func aspxServerCodeContext(normalized string) bool {
	if strings.Contains(normalized, "<%") {
		return true
	}
	if i := strings.Index(normalized, "<script"); i >= 0 {
		return strings.Contains(normalized[i:], "runat")
	}
	return false
}

// analyzeWebshell is the semantic analyzer entry point called from analyzer.go.
//
// Deliberately NOT guarded by securityDocumentContext. Those guards key on the
// mere presence of prose markers in text the attacker supplies in full, so on
// this path they act as a suppression oracle: prepending "## Description" plus
// 210 bytes of padding to a live shell body bought total suppression, in every
// category, end to end through the analyzer. See
// TestWebshellDocumentGuardIsNotAnEvasionOracle.
//
// FP separation is instead carried by requiring a server-side code delimiter
// per language (<?php / <?= for PHP, <% or <script runat= for ASPX). That is a
// requirement to fire rather than a licence to suppress, and an attacker cannot
// drop the delimiter and still have the shell execute. Prose that merely
// mentions a primitive in a sentence carries no delimiter and so cannot fire.
func analyzeWebshell(candidate semanticCandidate) (Hit, bool) {
	normalized := strings.ToLower(candidate.text)

	// PHP webshell: execution primitive + external input
	if (strings.Contains(normalized, "<?php") || strings.Contains(normalized, "<?=")) &&
		hasWebshellPrimitive(normalized) && hasExternalInput(normalized) {
		return hit(candidate, "webshell", engine.SeverityCritical, 0.95, map[string]bool{
			"syntax: PHP execution primitive with superglobal input":                  true,
			"semantics: attacker-controlled input reaches server-side code execution": true,
		}), true
	}

	// JSP webshell: Runtime.getRuntime() + request.getParameter, inside a JSP
	// server-side construct. The primitive pair alone is what a webshell scanner
	// report and a conference slide about webshell research both print in prose
	// ("检测到恶意函数: request.getParameter, Runtime.getRuntime()"), so the pair is
	// necessary but not sufficient. jspServerCodeContext supplies the same
	// requirement-to-fire the PHP and ASPX branches carry.
	if (strings.Contains(normalized, "runtime.getruntime()") || strings.Contains(normalized, "processbuilder")) &&
		(strings.Contains(normalized, "request.getparameter") || strings.Contains(normalized, "${param.")) &&
		jspServerCodeContext(normalized) {
		return hit(candidate, "webshell", engine.SeverityCritical, 0.93, map[string]bool{
			"syntax: Java process execution primitive with request parameter":            true,
			"semantics: attacker-controlled input reaches server-side process execution": true,
		}), true
	}

	// ASPX webshell: dynamic evaluation of request input, or a process start
	// sitting inside server-side code. eval(Request[ already carries input
	// reachability in the token itself. A bare system.diagnostics.process does
	// not: it is the ordinary .NET way to start any process and shows up in
	// prose, stack traces and framework source.
	//
	// What separates those from a shell is NOT request reachability. An uploaded
	// .aspx page that reaches Process.Start from a string literal, a server
	// control or a session value is still a shell — the file on disk is the
	// attack. Requiring a Request accessor here dropped exactly that class. What
	// prose never carries is a server-side code delimiter, and an attacker
	// cannot drop it and still have the page execute. See
	// TestWebshellDetectsProcessStartWithoutRequestInput.
	if strings.Contains(normalized, "eval(request[") ||
		(strings.Contains(normalized, "system.diagnostics.process") && aspxServerCodeContext(normalized)) {
		return hit(candidate, "webshell", engine.SeverityCritical, 0.92, map[string]bool{
			"syntax: ASP.NET process or dynamic evaluation primitive":     true,
			"semantics: request input reaches server-side code execution": true,
		}), true
	}

	// Webshell control interface: known filename + action parameter, and only on a
	// request-target surface.
	//
	// This branch asserts that the request being made IS a shell control request,
	// so it may only read the surface that carries the request target. Advisories
	// quote PoC URLs verbatim — "/data/manage/cmd.php?cmd=id" inside a markdown
	// disclosure is byte-identical to the attack, so no amount of shape analysis on
	// the string separates them; the only thing that differs is which surface it
	// arrived on. Scoping to uri/query is a requirement to fire, not a suppression:
	// an attacker cannot move the control interface out of the request target and
	// still reach the shell through it, and a POST whose path and parameters split
	// across surfaces is still covered by WebshellDetector.Detect, which reads the
	// URI and body together. See TestWebshellControlInterfaceIsSurfaceScoped.
	if requestTargetSurface(candidate.input.Source) &&
		rxWebshellPath.MatchString(normalized) &&
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
	// Common webshell filenames
	rxWebshellPath = regexp.MustCompile(`/(?:web)?shell\.php|/c(?:99|100)\.php|/r57\.php|/backdoor\.php|/cmd\.php|/[a-z0-9_-]*shell[a-z0-9_-]*\.(?:php|jsp|aspx)`)
)

func truncateWebshell(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
