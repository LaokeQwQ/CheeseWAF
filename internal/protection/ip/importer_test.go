package ip

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestParseThreatIntelPlainCIDR(t *testing.T) {
	items, err := ParseThreatIntel("cidr", []byte("203.0.113.10\n198.51.100.0/24 # scanners\n"), ImportOptions{Source: "unit", Severity: "high", Action: "block"})
	if err != nil {
		t.Fatalf("parse plain: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 indicators, got %d", len(items))
	}
	if items[1].Value != "198.51.100.0/24" || items[1].Action != "block" {
		t.Fatalf("unexpected indicator: %+v", items[1])
	}
}

func TestParseThreatIntelCSV(t *testing.T) {
	raw := "ip,severity,source,labels,action,confidence\n203.0.113.11,critical,feed-a,scanner|bot,block,95\n"
	items, err := ParseThreatIntel("csv", []byte(raw), ImportOptions{})
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one indicator, got %d", len(items))
	}
	if items[0].Severity != "critical" || items[0].Source != "feed-a" || items[0].Labels[1] != "bot" || items[0].Confidence != 0.95 {
		t.Fatalf("unexpected csv indicator: %+v", items[0])
	}
}

func TestParseThreatIntelSTIXPattern(t *testing.T) {
	raw := `{"type":"bundle","objects":[{"type":"indicator","pattern":"[ipv4-addr:value ISSUBSET '203.0.113.0/24']","labels":["botnet"]}]}`
	items, err := ParseThreatIntel("stix", []byte(raw), ImportOptions{Source: "stix-feed"})
	if err != nil {
		t.Fatalf("parse stix: %v", err)
	}
	if len(items) != 1 || items[0].Value != "203.0.113.0/24" {
		t.Fatalf("unexpected stix indicators: %+v", items)
	}
}

func TestParseThreatBookIPQueryShape(t *testing.T) {
	raw := `{"response_code":0,"data":{"203.0.113.44":{"judgments":["Scanner"],"intelligences":{"threatbook_lab":[{"source":"ThreatBook Labs","confidence":90,"expired":false,"intel_types":["Scanner"]}]}}}}`
	items, err := ParseThreatIntel("threatbook", []byte(raw), ImportOptions{Source: "ThreatBook", Action: "challenge"})
	if err != nil {
		t.Fatalf("parse threatbook: %v", err)
	}
	if len(items) != 1 || items[0].Value != "203.0.113.44" {
		t.Fatalf("expected ip from data map key, got %+v", items)
	}
	if items[0].Confidence != 0.9 || items[0].Source != "ThreatBook Labs" || len(items[0].Labels) == 0 {
		t.Fatalf("expected threatbook confidence/source/labels, got %+v", items[0])
	}
}

func TestParseThreatBookCleanOrEmptyLookupDoesNotCreateIndicator(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "empty data",
			raw:  `{"response_code":0,"data":{}}`,
		},
		{
			name: "empty ip object",
			raw:  `{"response_code":0,"data":{"203.0.113.45":{}}}`,
		},
		{
			name: "clean verdict",
			raw:  `{"response_code":0,"data":{"203.0.113.46":{"verdict":"clean","judgments":[],"intelligences":{}}}}`,
		},
		{
			name: "false listed flag",
			raw:  `{"data":{"203.0.113.47":{"listed":false,"score":0}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items, err := ParseThreatIntel("threatbook", []byte(tc.raw), ImportOptions{Source: "ThreatBook"})
			if err != nil {
				t.Fatalf("parse threatbook: %v", err)
			}
			if len(items) != 0 {
				t.Fatalf("expected no indicators for clean/empty lookup, got %+v", items)
			}
		})
	}
}

func TestParseThreatBookNestedIntelligenceWithoutJudgments(t *testing.T) {
	raw := `{"response_code":0,"data":{"203.0.113.48":{"intelligences":{"threatbook_lab":[{"source":"ThreatBook Labs","confidence":87,"intel_types":["C2"]}]}}}}`
	items, err := ParseThreatIntel("threatbook", []byte(raw), ImportOptions{Source: "ThreatBook", Action: "block"})
	if err != nil {
		t.Fatalf("parse threatbook: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one indicator from nested intelligence, got %+v", items)
	}
	if items[0].Value != "203.0.113.48" || items[0].Confidence != 0.87 || items[0].Source != "ThreatBook Labs" {
		t.Fatalf("unexpected nested intelligence indicator: %+v", items[0])
	}
}

func TestParseAbuseIPDBCheckShape(t *testing.T) {
	raw := `{"data":{"ipAddress":"203.0.113.60","abuseConfidenceScore":92,"totalReports":17,"usageType":"Data Center/Web Hosting/Transit","isWhitelisted":false}}`
	items, err := ParseThreatIntel("json", []byte(raw), ImportOptions{Source: "AbuseIPDB", Action: "block"})
	if err != nil {
		t.Fatalf("parse abuseipdb: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one AbuseIPDB indicator, got %+v", items)
	}
	if items[0].Value != "203.0.113.60" || items[0].Confidence != 0.92 || items[0].Action != "block" {
		t.Fatalf("unexpected AbuseIPDB indicator: %+v", items[0])
	}
}

func TestParseAbuseIPDBZeroScoreDoesNotImport(t *testing.T) {
	raw := `{"data":{"ipAddress":"203.0.113.61","abuseConfidenceScore":0,"totalReports":0,"isWhitelisted":false}}`
	items, err := ParseThreatIntel("json", []byte(raw), ImportOptions{Source: "AbuseIPDB"})
	if err != nil {
		t.Fatalf("parse abuseipdb clean: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected clean AbuseIPDB lookup to import nothing, got %+v", items)
	}
}

func TestParseOTXPulseInfoShape(t *testing.T) {
	raw := `{"indicator":"203.0.113.62","type":"IPv4","pulse_info":{"count":2,"pulses":[{"name":"scanner infrastructure","tags":["scanner","botnet"]}]}}`
	items, err := ParseThreatIntel("json", []byte(raw), ImportOptions{Source: "AlienVault OTX", Action: "challenge"})
	if err != nil {
		t.Fatalf("parse otx: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one OTX indicator, got %+v", items)
	}
	if items[0].Value != "203.0.113.62" || len(items[0].Labels) == 0 {
		t.Fatalf("unexpected OTX indicator: %+v", items[0])
	}
}

func TestParseOTXZeroPulseDoesNotImport(t *testing.T) {
	raw := `{"indicator":"203.0.113.63","type":"IPv4","pulse_info":{"count":0,"pulses":[]}}`
	items, err := ParseThreatIntel("json", []byte(raw), ImportOptions{Source: "AlienVault OTX"})
	if err != nil {
		t.Fatalf("parse clean otx: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected OTX zero-pulse lookup to import nothing, got %+v", items)
	}
}

func TestParseMISPAttributeShape(t *testing.T) {
	raw := `{"response":[{"Event":{"Attribute":[{"type":"ip-src","category":"Network activity","value":"203.0.113.64","to_ids":true,"Tag":[{"name":"misp-galaxy:threat-actor=\"scanner\""}]}]}}]}`
	items, err := ParseThreatIntel("misp", []byte(raw), ImportOptions{Source: "MISP", Action: "block"})
	if err != nil {
		t.Fatalf("parse misp: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one MISP indicator, got %+v", items)
	}
	if items[0].Value != "203.0.113.64" || items[0].Action != "block" {
		t.Fatalf("unexpected MISP indicator: %+v", items[0])
	}
}

func TestWalkJSONStopsAtDepthLimit(t *testing.T) {
	nested := any("203.0.113.77")
	for i := 0; i < 80; i++ {
		nested = map[string]any{"objects": []any{nested}}
	}
	raw, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	items, err := ParseThreatIntel("json", raw, ImportOptions{Source: "depth"})
	if err != nil {
		t.Fatalf("parse nested json: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("depth-limited walk must not import buried indicators, got %+v", items)
	}
}

func TestMergeThreatIntelUpdatesExisting(t *testing.T) {
	old := []config.ThreatIntelConfig{{Value: "203.0.113.10", Source: "old", Severity: "low"}}
	next := []config.ThreatIntelConfig{{Value: "203.0.113.10", Source: "new", Severity: "high"}, {Value: "198.51.100.1", Source: "new"}}
	merged := MergeThreatIntel(old, next)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged indicators, got %d", len(merged))
	}
	if merged[0].Source != "new" || merged[0].Severity != "high" {
		t.Fatalf("expected existing indicator to update: %+v", merged[0])
	}
}

func TestParseThreatIntelRejectsUnknownFormat(t *testing.T) {
	if _, err := ParseThreatIntel("vendor-proprietary", []byte("203.0.113.99\n"), ImportOptions{Source: "feed"}); err == nil {
		t.Fatal("expected unsupported format to fail instead of importing zero indicators")
	}
}

func TestCanonicalIndicatorSupportedTypes(t *testing.T) {
	cases := []struct {
		name, typ, value, wantType, wantValue string
	}{
		{"domain", "domain-name", "WWW.Example.COM.", "domain", "www.example.com"},
		{"url", "url", "https://Example.COM/path#fragment", "url", "https://example.com/path"},
		{"sha256", "file:hashes.SHA-256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "sha256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"md5", "md5", "0123456789ABCDEF0123456789ABCDEF", "md5", "0123456789abcdef0123456789abcdef"},
		{"asn", "autonomous-system", "AS64500", "asn", "64500"},
		{"ja3", "ja3", "0123456789abcdef0123456789abcdef", "ja3", "0123456789abcdef0123456789abcdef"},
		{"ja4", "ja4", "t13d1516h2_8daaf6152771_0273b62f6f95", "ja4", "t13d1516h2_8daaf6152771_0273b62f6f95"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			typ, value, ok := CanonicalIndicator(tc.typ, tc.value)
			if !ok || typ != tc.wantType || value != tc.wantValue {
				t.Fatalf("CanonicalIndicator(%q, %q) = (%q, %q, %v), want (%q, %q, true)", tc.typ, tc.value, typ, value, ok, tc.wantType, tc.wantValue)
			}
		})
	}
}

func TestCanonicalIndicatorRejectsOversizedCIDR(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "198.51.100.0/7", "2001:db8::/8"} {
		if typ, canonical, ok := CanonicalIndicator("cidr", value); ok {
			t.Fatalf("accepted oversized CIDR %q as %s:%s", value, typ, canonical)
		}
	}
}

func TestParseSTIXTypedPatterns(t *testing.T) {
	raw := `{"type":"bundle","objects":[
{"type":"indicator","pattern":"[domain-name:value = 'evil.example']"},
{"type":"indicator","pattern":"[url:value = 'https://evil.example/path']"},
{"type":"indicator","pattern":"[file:hashes.'SHA-256' = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef']"},
{"type":"indicator","pattern":"[autonomous-system:number = 'AS64500']"},
{"type":"indicator","pattern":"[network-traffic:extensions.'ja3-fingerprint' = '0123456789abcdef0123456789abcdef']"}
]}`
	items, err := ParseThreatIntel("stix", []byte(raw), ImportOptions{Source: "stix"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, item := range items {
		got[item.Type+":"+item.Value] = true
	}
	for _, want := range []string{
		"domain:evil.example",
		"url:https://evil.example/path",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"asn:64500",
		"ja3:0123456789abcdef0123456789abcdef",
	} {
		if !got[want] {
			t.Errorf("missing STIX indicator %s in %#v", want, got)
		}
	}
}

func TestMergeThreatIntelTrustAndActionGuards(t *testing.T) {
	existing := []config.ThreatIntelConfig{
		{Value: "203.0.113.90", Type: "ip", Source: "verified:feed", Severity: "high", Action: "challenge"},
		{Value: "203.0.113.91", Type: "ip", Source: "feed", Severity: "low", Action: "challenge"},
		{Value: "203.0.113.92", Type: "ip", Source: "feed", Severity: "low", Action: "block", ExpiresAt: time.Now().Add(-time.Minute)},
	}
	imported := []config.ThreatIntelConfig{
		{Value: "203.0.113.90", Type: "ip", Source: "feed", Severity: "critical", Action: "block"},
		{Value: "203.0.113.91", Type: "ip", Source: "feed", Severity: "high", Action: "block"},
		{Value: "203.0.113.93", Type: "ip", Source: "feed", Action: "block"},
	}
	merged := MergeThreatIntel(existing, imported)
	if len(merged) != 3 {
		t.Fatalf("expected expired item removed and new item retained, got %d: %+v", len(merged), merged)
	}
	byValue := map[string]config.ThreatIntelConfig{}
	for _, item := range merged {
		byValue[item.Value] = item
	}
	if byValue["203.0.113.90"].Source != "verified:feed" || byValue["203.0.113.90"].Action != "challenge" {
		t.Fatalf("low-trust feed replaced/escalated trusted item: %+v", byValue["203.0.113.90"])
	}
	if byValue["203.0.113.91"].Action != "challenge" {
		t.Fatalf("incoming action escalated existing action: %+v", byValue["203.0.113.91"])
	}
}
