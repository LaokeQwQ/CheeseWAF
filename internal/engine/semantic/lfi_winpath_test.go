package semantic

import (
	"net/url"
	"testing"
)

// The LFI model was Unix-shaped end to end: every sensitive target the engine
// knew was /etc/passwd, /proc/self/environ, .ssh/id_rsa. A Windows host's
// equivalents produced no signal whatsoever — "C:\Windows\System32\drivers\etc\hosts"
// scored zero attack hints, so analyzeLFI was never even called. Ten of the
// verified misses were this, and they are the visible edge of a whole-platform
// hole rather than ten stray payloads.
func TestWindowsAbsolutePathLFI(t *testing.T) {
	cases := []struct {
		name, target, ct, body string
	}{
		{"system32-hosts", "/api/v1/file/load", "application/json", `{"filePath":"C:\\Windows\\System32\\drivers\\etc\\hosts"}`},
		{"programdata", "/app/user/update", "application/json", `{"filePath":"C:\\ProgramData\\app\\config\\settings.json"}`},
		{"users-public", "/api/v3/items/search", "application/json", `{"filePath":"C:\\Users\\Public\\Documents\\config.xml"}`},
		{"inetpub-webconfig", "/blog/article/view", "application/json", `{"filePath":"C:\\inetpub\\wwwroot\\web.config"}`},
		{"d-drive-secrets", "/api/config/get", "application/json", `{"filePath":"D:\\Data\\Profiles\\user\\secrets.ini"}`},
		{"form-encoded", "/load", "application/x-www-form-urlencoded", `path=C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts`},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "POST", tc.target, tc.ct, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected detection, got none")
			}
			if got.Category != "lfi" {
				t.Errorf("category = %q, want lfi", got.Category)
			}
		})
	}
}

// TestOverlongUTF8Traversal pins the whole overlong family. Only the 2-byte
// "%c0%af" was covered before; the 3-byte "%e0%80%af" form walked through even
// though it decodes to the same "../" after UTF-8 normalisation.
func TestOverlongUTF8Traversal(t *testing.T) {
	cases := []struct{ name, payload string }{
		{"c0af", `..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`},
		{"c0ae", `..%c0%ae..%c0%af..%c0%ae..%c0%afvar%c0%aflog%c0%afaccess.log`},
		{"e080af", `..%e0%80%af..%e0%80%af..%e0%80%afconfig%e0%80%afsecret.yaml`},
		{"c1-9c", `..%c1%9c..%c1%9cetc%c1%9cpasswd`},
		{"double-encoded", `..%25c0%25af..%25c0%25afetc%25c0%25afpasswd`},
	}
	a := NewAnalyzer("block", 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/file/view?template="+tc.payload, "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected detection for %s, got none", tc.name)
			}
		})
	}
}

// TestWindowsPathInProseIsNotAnAttack guards the obvious false-positive shape.
// ":\" now opens LFI analysis, so ordinary Windows paths in documentation,
// telemetry and user-agent strings have to stay clean.
func TestWindowsPathInProseIsNotAnAttack(t *testing.T) {
	benign := []string{
		`C:\Users\bob\Documents\notes.txt`,
		`C:\Users\alice\Pictures\vacation.jpg`,
		`D:\Games\Steam\steamapps\common\Half-Life`,
		`The installer copies files to C:\Program Files\CheeseWAF and starts the service.`,
		`Saved report to C:\Users\admin\Downloads\report-2026-08-30.xlsx`,
	}
	a := NewAnalyzer("block", 2)
	for _, in := range benign {
		got := detectOnTarget(t, a, "GET", "/note?text="+url.QueryEscape(in), "", "")
		if got != nil && got.Detected {
			t.Errorf("benign Windows path %q detected as %s", in, got.Category)
		}
	}
}
