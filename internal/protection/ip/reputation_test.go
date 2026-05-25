package ip

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestIntelMatchesCIDR(t *testing.T) {
	intel, err := NewIntel([]config.ThreatIntelConfig{
		{ID: "feed-1", Value: "203.0.113.0/24", Severity: "high", Source: "test", Enabled: true},
	})
	if err != nil {
		t.Fatalf("new intel: %v", err)
	}
	matches := intel.Match("203.0.113.10")
	if len(matches) != 1 || matches[0].Severity != "high" {
		t.Fatalf("expected high severity match, got %+v", matches)
	}
}

func TestTaggerNormalizesTags(t *testing.T) {
	tagger := NewTagger(map[string][]string{"203.0.113.10": []string{"SQLI, Bot", "bot"}})
	tags := tagger.Tags("203.0.113.10")
	if len(tags) != 2 || tags[0] != "bot" || tags[1] != "sqli" {
		t.Fatalf("unexpected tags: %+v", tags)
	}
}

func TestBuildReputationProfilesScoresThreats(t *testing.T) {
	profiles, err := BuildReputationProfiles(config.IPProtectionConfig{
		Blacklist: []string{"198.51.100.7"},
		Tags:      map[string][]string{"198.51.100.7": []string{"sqli", "repeat"}},
		ThreatIntel: []config.ThreatIntelConfig{
			{ID: "feed-1", Value: "198.51.100.7", Severity: "high", Enabled: true},
		},
	}, []storage.LogEntry{
		{ClientIP: "198.51.100.7", Action: "block", Category: "sqli"},
	})
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Reputation > 10 {
		t.Fatalf("expected low reputation profile, got %+v", profiles)
	}
}
