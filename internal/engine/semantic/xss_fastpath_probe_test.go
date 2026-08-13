package semantic

import "testing"

// TestExecutableXSSContextKeepsFullPatternCoverage pins the invariant that any
// pre-filter placed in front of the XSS regex battery must be a strict superset
// of what those patterns match. A bare-substring gate is not: it silently
// swallows whitespace-evaded tags, generic event handlers, charset vectors and
// encoding chains that xssPatterns/xssModernPatterns do match.
//
// Every payload below is matched by the regex battery. If a gate drops any of
// them, executableXSSContext under-reports and both XSSDetector.Detect and
// heuristicScores lose the category.
func TestExecutableXSSContextKeepsFullPatternCoverage(t *testing.T) {
	payloads := []struct {
		name    string
		payload string
	}{
		{"whitespace evaded script tag", "< script >alert(1)</script>"},
		{"namespaced script tag", "<xhtml:script>alert(1)</xhtml:script>"},
		{"generic event handler onpageshow", "<body onpageshow=alert(1)>"},
		{"generic event handler ontoggle", "<details ontoggle=alert(1)>"},
		{"pointer event handler", "<div onpointerdown=alert(1)>"},
		{"transition event handler", "<div ontransitionend=alert(1)>"},
		{"animation event handler", "<div onanimationstart=alert(1)>"},
		{"embed javascript src", "<embed src='javascript:alert(1)'>"},
		{"object javascript data", "<object data='javascript:alert(1)'>"},
		{"math href javascript", "<math href='javascript:alert(1)'>"},
		{"tag break into img", "'></style><img src=x onerror=alert(1)>"},
		{"button formaction", "<button formaction='javascript:alert(1)'>"},
		{"video poster", "<video poster='javascript:alert(1)'>"},
		{"audio src javascript", "<audio src='javascript:alert(1)'>"},
		{"xml stylesheet", "<?xml-stylesheet href='javascript:alert(1)'?>"},
		{"utf7 charset", `charset="x-imap4-modified-utf7"`},
		{"mac farsi charset", "x-mac-farsi"},
		{"browser crypto api", "crypto.generateCRMFRequest("},
		{"body onscroll alert", "<body onscroll=alert(1)>"},
		{"input onfocus write", "<input onfocus=write>"},
		{"redos pattern attr", `<input pattern="^((a+?.)a)+$">`},
		{"hex encoded call chain", `\x61\x6c\x65\x72\x74 alert(`},
		{"opera css link", `style="-o-link:'javascript:alert(1)'"`},
		{"template repeat", "<x repeat=template>"},
		{"worker importscripts", "importScripts('data:text/javascript,alert(1)')"},
		{"dom set innerHTML", "set('innerHTML', payload)"},
		{"js shorthand exec", "call(alert)"},
		{"js comment obfuscation", "/**/"},
		{"svg xlink data uri", "<a xlink:href='data:text/html;base64,PHN2Zz4='>"},
		{"frame javascript src", "<frame src='javascript:alert(1)'>"},
		{"decimal entity chain", "&#60;&#62;&#60;&#62;"},
		{"iframe srcdoc", "<iframe srcdoc='<script>alert(1)</script>'>"},
		{"meta refresh javascript", "<meta content='0;url=javascript:alert(1)'>"},
		{"style expression", `<div style="width:expression(alert(1))">`},
		{"style tag css injection", "<style>@import url(javascript:alert(1))</style>"},
		{"href javascript url", "<a href='javascript:alert(1)'>"},
		{"data url text html", "<a href='data:text/html,<script>alert(1)</script>'>"},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			normalized := normalize(tc.payload)
			if !executableXSSContext(normalized) {
				t.Fatalf("executableXSSContext dropped a payload the regex battery matches:\n  payload:    %q\n  normalized: %q\nA pre-filter in front of the XSS patterns must be a superset of them.", tc.payload, normalized)
			}
		})
	}
}
