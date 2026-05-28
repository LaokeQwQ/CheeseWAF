package ip

import (
	"encoding/json"
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

func TestBuildReputationProfilesReturnsJSONSafeEmptyCollections(t *testing.T) {
	profiles, err := BuildReputationProfiles(config.IPProtectionConfig{
		Whitelist: []string{"203.0.113.10"},
	}, nil)
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected one profile, got %+v", profiles)
	}
	if profiles[0].Tags == nil {
		t.Fatalf("expected tags to be an empty array, got nil")
	}
	if profiles[0].Intel == nil {
		t.Fatalf("expected intel to be an empty array, got nil")
	}
	if profiles[0].Stats.ByType == nil {
		t.Fatalf("expected stats.by_type to be an empty object, got nil")
	}
	raw, err := json.Marshal(profiles[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) == "" || containsJSONNull(raw, "tags") || containsJSONNull(raw, "intel") || containsJSONNull(raw, "by_type") {
		t.Fatalf("profile still contains null collections: %s", raw)
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

func containsJSONNull(raw []byte, field string) bool {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return false
	}
	if value, ok := decoded[field]; ok {
		return value == nil
	}
	stats, ok := decoded["stats"].(map[string]any)
	if !ok {
		return false
	}
	return stats[field] == nil
}
