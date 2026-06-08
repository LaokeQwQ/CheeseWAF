package ip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestGeoIPPolicyCountryCIDRLookup(t *testing.T) {
	policy, err := NewGeoIPPolicy(config.GeoIPConfig{
		Enabled:          true,
		BlockedCountries: []string{"us"},
		CountryCIDRs: map[string][]string{
			"us": {"203.0.113.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("NewGeoIPPolicy returned error: %v", err)
	}

	if country := policy.Country("203.0.113.7"); country != "US" {
		t.Fatalf("Country() = %q, want US", country)
	}
	if !policy.Blocked("203.0.113.7") {
		t.Fatal("Blocked() = false, want true")
	}
	if policy.Blocked("198.51.100.1") {
		t.Fatal("Blocked() = true for an unmapped IP, want false")
	}

	location := policy.Lookup("203.0.113.7")
	if location.CountryCode != "US" {
		t.Fatalf("Lookup().CountryCode = %q, want US", location.CountryCode)
	}
	if location.Source != "cidr" {
		t.Fatalf("Lookup().Source = %q, want cidr", location.Source)
	}
	metadata := location.Metadata()
	if metadata["country_code"] != "US" {
		t.Fatalf("metadata country_code = %#v, want US", metadata["country_code"])
	}
	if metadata["source"] != "cidr" {
		t.Fatalf("metadata source = %#v, want cidr", metadata["source"])
	}
}

func TestGeoIPPolicyRejectsInvalidCIDR(t *testing.T) {
	_, err := NewGeoIPPolicy(config.GeoIPConfig{
		CountryCIDRs: map[string][]string{
			"US": {"not-a-cidr"},
		},
	})
	if err == nil {
		t.Fatal("NewGeoIPPolicy returned nil error for invalid CIDR")
	}
}

func TestGeoIPPolicyIgnoresMissingDatabase(t *testing.T) {
	policy, err := NewGeoIPPolicy(config.GeoIPConfig{
		Database: filepath.Join(t.TempDir(), "missing.mmdb"),
	})
	if err != nil {
		t.Fatalf("NewGeoIPPolicy returned error for missing optional database: %v", err)
	}
	if country := policy.Country("203.0.113.7"); country != "" {
		t.Fatalf("Country() = %q without CIDR/mmdb data, want empty", country)
	}
}

func TestGeoIPPolicyRejectsInvalidDatabase(t *testing.T) {
	database := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(database, []byte("not an mmdb"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := NewGeoIPPolicy(config.GeoIPConfig{Database: database})
	if err == nil {
		t.Fatal("NewGeoIPPolicy returned nil error for invalid database")
	}
}
