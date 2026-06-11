package ip

import (
	"testing"

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
