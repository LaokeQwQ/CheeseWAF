package semantic

import (
	"strings"
	"unicode"
)

const (
	isolationUnknown  = ""
	isolationIsolated = "isolated"
	isolationEmbedded = "embedded"
)

// classifyPayloadIsolation reports whether a candidate value is almost only an
// attack gadget (isolated) or the same gadget sitting inside other text
// (embedded). Path and parameter names are out of scope; callers pass one
// decoded field value.
func classifyPayloadIsolation(text string) string {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return isolationUnknown
	}
	// A live server-side delimiter plus a gadget is an uploaded shell even
	// when an attacker prefixes prose. Quoted eval() without <?php stays on
	// the leftover-prose path.
	if liveServerCodeGadget(raw) {
		return isolationIsolated
	}
	// Peel Log4j wrappers first so ${${::-j}ndi:...} is compared as ${jndi:...}.
	work := strings.TrimSpace(peelLog4jLookups(raw))
	if work == "" {
		work = raw
	}
	gadget := extractPrimaryGadget(work)
	if gadget == "" {
		return isolationUnknown
	}
	leftover := stripGadgetOnce(work, gadget)
	leftover = stripThinWrappers(leftover)
	if leftoverLooksLikeProse(leftover) {
		return isolationEmbedded
	}
	return isolationIsolated
}

func liveServerCodeGadget(text string) bool {
	n := strings.ToLower(text)
	if strings.Contains(n, "<?php") || strings.Contains(n, "<?=") {
		return rxPHPEvalSuperglobal.MatchString(n) ||
			(hasWebshellPrimitive(n) && hasExternalInput(n))
	}
	if strings.Contains(n, "<%") || strings.Contains(n, "<jsp:") {
		return strings.Contains(n, "runtime.getruntime()") ||
			strings.Contains(n, "eval(request[") ||
			strings.Contains(n, "system.diagnostics.process")
	}
	return false
}

func extractPrimaryGadget(text string) string {
	lower := strings.ToLower(text)
	peeled := strings.ToLower(peelLog4jLookups(text))
	if loc := rxPHPEvalSuperglobal.FindStringIndex(lower); loc != nil {
		return lower[loc[0]:loc[1]]
	}
	if loc := rxPHPCallbackSuperglobal.FindStringIndex(lower); loc != nil {
		return lower[loc[0]:loc[1]]
	}
	if (strings.Contains(lower, "eval(") || strings.Contains(lower, "assert(")) &&
		(strings.Contains(lower, "getallheaders") || strings.Contains(lower, "apache_request_headers")) {
		start := strings.Index(lower, "eval(")
		if start < 0 || (strings.Contains(lower, "assert(") && strings.Index(lower, "assert(") < start) {
			start = strings.Index(lower, "assert(")
		}
		end := strings.LastIndex(lower, ")")
		if start >= 0 && end > start {
			return lower[start : end+1]
		}
	}
	if loc := rxLog4ShellJNDI.FindStringIndex(peeled); loc != nil {
		end := loc[1]
		if i := strings.Index(peeled[end:], "}"); i >= 0 {
			end += i + 1
		}
		return peeled[loc[0]:end]
	}
	if quotedOrPredicateInjection(text) && len([]rune(strings.TrimSpace(text))) <= 96 {
		return strings.ToLower(strings.TrimSpace(text))
	}
	return ""
}

func stripGadgetOnce(text, gadget string) string {
	lower := strings.ToLower(text)
	g := strings.ToLower(gadget)
	i := strings.Index(lower, g)
	if i < 0 {
		return text
	}
	end := i + len(g)
	// leftover is only used for prose detection. Work on the lowercased
	// string so Unicode case-folding cannot panic when it changes length.
	if end > len(lower) {
		return lower[:i]
	}
	return lower[:i] + lower[end:]
}

func stripThinWrappers(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "@;/${}()[]<>\"'` \t\r\n")
	return strings.TrimSpace(s)
}

func leftoverLooksLikeProse(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Nested JNDI hosts (${sys:java.version}.evil.example) are part of the
	// lookup, not surrounding sentences.
	if hostLikeLeftover(s) {
		return false
	}
	letters := 0
	words := 0
	inWord := false
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			letters++
			if letters >= 4 {
				return true
			}
			continue
		}
		if unicode.IsLetter(r) {
			if !inWord {
				words++
				inWord = true
			}
			continue
		}
		inWord = false
	}
	return words >= 2 || letters >= 4
}

func hostLikeLeftover(s string) bool {
	t := strings.Trim(s, "/.}{:$")
	if t == "" || strings.ContainsAny(t, " \t\n") {
		return t == ""
	}
	return strings.Contains(t, ".") || strings.Contains(t, "/")
}
