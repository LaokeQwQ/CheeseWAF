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

func TestGeoIPLocationMetadataIncludesPrecisionFields(t *testing.T) {
	location := GeoIPLocation{
		CountryCode:  "CN",
		CountryName:  "中国",
		Continent:    "AS",
		City:         "杭州",
		Region:       "浙江",
		RegionCode:   "ZJ",
		District:     "西湖区",
		DistrictCode: "XH",
		Street:       "文三路",
		StreetCode:   "WSL",
		Latitude:     30.259,
		Longitude:    120.13,
		Accuracy:     12,
		Source:       "mmdb",
	}

	metadata := location.Metadata()
	for key, want := range map[string]any{
		"country_code":    "CN",
		"city":            "杭州",
		"region":          "浙江",
		"district":        "西湖区",
		"district_code":   "XH",
		"street":          "文三路",
		"street_code":     "WSL",
		"lat":             30.259,
		"lon":             120.13,
		"accuracy_radius": uint16(12),
		"source":          "mmdb",
	} {
		if got := metadata[key]; got != want {
			t.Fatalf("metadata[%s] = %#v, want %#v", key, got, want)
		}
	}
}

func TestGeoIPPolicyPrecisionDatabaseAddsStreetLevelLocation(t *testing.T) {
	database := filepath.Join(t.TempDir(), "precision.json")
	raw := []byte(`{
  "records": [
    {
      "cidr": "203.0.113.0/24",
      "country_code": "CN",
      "country_name": "中国",
      "continent": "AS",
      "region": "浙江",
      "region_code": "ZJ",
      "city": "杭州",
      "district": "西湖区",
      "street": "文三路",
      "lat": 30.259,
      "lon": 120.13,
      "accuracy_radius": 2,
      "source": "local-precision"
    },
    {
      "cidr": "203.0.113.7/32",
      "city": "杭州",
      "district": "西湖区",
      "street": "学院路",
      "lat": 30.267,
      "lon": 120.122,
      "accuracy_radius": 1,
      "source": "local-precision-host"
    }
  ]
}`)
	if err := os.WriteFile(database, raw, 0o600); err != nil {
		t.Fatalf("write precision database: %v", err)
	}
	policy, err := NewGeoIPPolicy(config.GeoIPConfig{PrecisionDatabase: database})
	if err != nil {
		t.Fatalf("NewGeoIPPolicy returned error: %v", err)
	}
	location := policy.Lookup("203.0.113.7")
	if location.CountryCode != "CN" || location.City != "杭州" || location.District != "西湖区" || location.Street != "学院路" {
		t.Fatalf("unexpected precision location: %+v", location)
	}
	if location.Accuracy != 1 || location.Source != "local-precision-host" {
		t.Fatalf("unexpected precision metadata: %+v", location)
	}
}
