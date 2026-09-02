package semantic

import "strings"

// rcePatternMayMatch is a sound, allocation-free prefilter for rcePatterns.
// Each branch checks a literal that every match of the corresponding regular
// expression must contain. It is deliberately a necessary-condition check:
// returning true only means that the regexp is worth running; returning false
// means the regexp cannot match this candidate. Keeping these checks separate
// from the expressions preserves the detector's matching semantics while
// avoiding a full scan by the expensive patterns on ordinary prose.
//
// lower must already be a lower-cased view of the same text that the regexp
// will inspect. analyzeRCE uses its raw, control-preserving lowercase view.
func rcePatternMayMatch(index int, lower string) bool {
	switch index {
	case 0: // shell separator/newline followed by a command
		return rceContainsAny(lower, ";", "&&", "||", "|", "\n", "\r")
	case 1: // $(...) or backtick command substitution
		return rceContainsAny(lower, "$(", "`")
	case 2: // shell executable path / Windows shell binary
		return rceContainsAny(lower, "/bin/", "cmd.exe", "powershell.exe", "pwsh.exe")
	case 3: // download-to-shell chain
		return rceContainsAny(lower, "curl", "wget", "fetch", "lynx")
	case 4: // shell -c invocation
		return rceContainsAny(lower, "bash", "sh", "zsh", "dash", "ksh", "tcsh", "csh")
	case 5: // Windows cmd /c
		return strings.Contains(lower, "cmd")
	case 6: // encoded PowerShell command
		return rceContainsAny(lower, "powershell", "pwsh")
	case 7: // PowerShell dynamic execution
		return rceContainsAny(lower,
			"iex", "invoke-expression", "invoke-command", "start-process", "new-object",
			".invoke", ".ps1", "downloadstring", "net.webclient", "frombase64string",
			"wmi", "comobject", "microsoft.win32")
	case 8: // inline interpreter invocation
		return rceContainsAny(lower, "python", "perl", "php", "ruby", "node", "lua")
	case 9: // qualified interpreter/binary alias
		return strings.Contains(lower, "/bin/")
	case 10: // command reading a sensitive local path
		return rceContainsAny(lower, "/etc/", "/proc/", "/var/", "/root/", "/home/") &&
			rceContainsAny(lower, "cat", "head", "tail", "less", "more", "type", "xxd", "hexdump", "od")
	case 11: // $SHELL / ${SHELL}
		return rceContainsAny(lower, "$shell", "${shell}")
	case 12: // /dev/tcp reverse shell
		return strings.Contains(lower, "/dev/tcp") &&
			rceContainsAny(lower, "bash", "sh", "zsh", "dash")
	case 13: // nc -e reverse shell
		return rceContainsAny(lower, "nc", "ncat", "netcat")
	case 14: // language socket reverse shell
		return rceContainsAny(lower, "python", "perl", "ruby", "php")
	case 15: // ${IFS} whitespace evasion
		return strings.Contains(lower, "ifs")
	case 16: // file-descriptor redirection
		return rceContainsAny(lower, ">&", "/dev/", ">")
	case 17, 18: // PowerShell obfuscation/advanced flags
		return rceContainsAny(lower, "powershell", "pwsh")
	case 19: // variable assignment after a shell/encoded separator
		return rceContainsAny(lower, ";", "&&", "||", "|", "&", "\n", "\r", "%0a", "%0d", "%3a", "%3b") &&
			strings.Contains(lower, "=")
	case 20: // encoded/chained execution phases
		return rceContainsAny(lower, "frombase64", "base64_decode", "atob", "downloadstring", "eval")
	default:
		// A newly appended pattern must be evaluated until its necessary marker is
		// reviewed and added here. This fail-open default protects recall.
		return true
	}
}

// rcePatternMayMatchViews evaluates both lowercase views used by the analyzer:
// rawLower preserves control bytes such as newlines, while normalizedLower
// applies NFKC compatibility folding so regexp Unicode simple-fold matches (for
// example, long s in "ſh") cannot be rejected by an ASCII marker gate.
func rcePatternMayMatchViews(index int, rawLower, normalizedLower string) bool {
	if rcePatternMayMatch(index, rawLower) {
		return true
	}
	return normalizedLower != rawLower && rcePatternMayMatch(index, normalizedLower)
}

func rceContainsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func rceShellControlMayMatch(lower string) bool {
	return rceContainsAny(lower, ";", "&&", "||", "|", "$(", "`")
}

func rceShellMetacharCommandMayMatch(lower string) bool {
	return rceContainsAny(lower, ";", "&&", "||", "|") &&
		rceContainsAny(lower,
			"cat", "id", "whoami", "uname", "curl", "wget", "bash", "sh", "zsh", "dash",
			"pwsh", "powershell", "cmd", "python", "perl", "php", "ruby", "node", "nc", "ncat",
			"netcat", "netstat", "socat", "telnet", "tftp", "dig", "nslookup", "host", "arp",
			"ifconfig", "lua", "gawk", "awk", "sed", "tr", "iex", "type", "dir", "ls", "sleep",
			"echo", "ping", "lsof")
}

func rceMetacharExecutionFunctionMayMatch(lower string) bool {
	return rceContainsAny(lower, ";", "&&", "||", "|") &&
		rceContainsAny(lower, "system", "exec", "passthru", "shell_exec", "popen", "eval", "assert")
}

func rcePowerShellSideFxMayMatch(lower string) bool {
	return rceContainsAny(lower,
		"powershell", "pwsh", "downloadstring", "downloadfile", "frombase64string",
		"invoke-expression", "iex", "new-object", "webclient")
}

func rceNetWebClientSideFxMayMatch(lower string) bool {
	return rceContainsAny(lower,
		"new-object", "system.net.webclient", "downloadfile", "downloadstring", "iwr", "invoke-webrequest")
}

func rceEncodedPowerShellMayMatch(lower string) bool {
	return rceContainsAny(lower, "powershell", "pwsh")
}

func rceWhitespaceEvasionMayMatch(lower string) bool {
	// The regexp accepts both braced and unbraced forms, including a partially
	// closed "${ifs" sequence. The invariant marker is therefore just "ifs".
	return strings.Contains(lower, "ifs")
}

func rceInterpreterInlineMayMatch(lower string) bool {
	return rceContainsAny(lower,
		"bash", "sh", "zsh", "dash", "ksh", "cmd", "python", "perl", "php", "ruby", "node", "lua")
}

func rceDownloadExecChainMayMatch(lower string) bool {
	return rceContainsAny(lower, "curl", "wget", "fetch", "busybox")
}

func rceReverseShellPrimitiveMayMatch(lower string) bool {
	return rceContainsAny(lower, "/dev/tcp", "/dev/udp", "nc", "ncat", "netcat", "bash", "socket.socket", "child_process")
}

func rcePowerShellReverseShellMayMatch(lower string) bool {
	return rceContainsAny(lower, "tcpclient", "getstream", "net.sockets.tcpclient", "while")
}

func rceTemplateExecutionPrimitiveMayMatch(lower string) bool {
	return rceContainsAny(lower,
		"registerundefinedfiltercallback", "filter", "system", "exec", "popen", "passthru", "shell_exec")
}

func rceLoaderPrimitiveMayMatch(lower string) bool {
	return rceContainsAny(lower,
		"ld_preload", "dyld_insert_libraries", "process.dlopen", "ctypes.cdll", "classloader",
		"defineclass", "unsafe.defineanonymousclass", "reflection.emit", "assembly.load")
}
