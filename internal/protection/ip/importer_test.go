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
