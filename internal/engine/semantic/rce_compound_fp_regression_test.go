package semantic

import (
	"net/url"
	"testing"
)

// Compound command fields occur in build metadata and diagnostics. An output
// command that merely prints the word "id" must not be treated as execution.
func TestRCECompoundSinksIgnoreEchoAndOutputArguments(t *testing.T) {
	clean := []string{
		"/docs?cmd.exe=" + url.QueryEscape("cmd.exe /c echo id"),
		"/docs?command_line=" + url.QueryEscape("powershell -NoProfile -Command Write-Output id"),
		"/docs?command_line=" + url.QueryEscape("bash -c echo id"),
		"/docs?command_line=" + url.QueryEscape(`powershell -NoProfile -Command Write-Output "/etc/passwd"`),
		"/docs?command_line=" + url.QueryEscape(`cmd.exe /c curl "https://example.com/health?a=1&b=2"`),
		"/docs?command_line=" + url.QueryEscape(`powershell -Command Write-Output "C:\\Windows\\System32"`),
		"/docs?command_line=" + url.QueryEscape(`cmd.exe /c echo "C:\\Windows\\System32"`),
	}
	for _, target := range clean {
		t.Run(target, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "GET", target, "", "")
			if got != nil && got.Detected {
				t.Fatalf("output-only command was treated as RCE: %+v", got)
			}
		})
	}
}

func TestRCECompoundSinksKeepCommandAndFileReadSignals(t *testing.T) {
	positives := []string{
		"/run?command_line=" + url.QueryEscape("bash -c id"),
		"/run?command_line=" + url.QueryEscape(`python3 -c "print(open('/etc/passwd').read())"`),
		"/run?cmd.exe=" + url.QueryEscape(`cmd.exe /c type C:\\Windows\\win.ini`),
		"/run?command_line=" + url.QueryEscape(`bash -c 'echo ok; whoami'`),
	}
	for _, target := range positives {
		t.Run(target, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 5, "rce"), "GET", target, "", "")
			if got == nil || !got.Detected || got.Category != "rce" {
				t.Fatalf("high-confidence command/file-read signal was missed: %+v", got)
			}
		})
	}
}
