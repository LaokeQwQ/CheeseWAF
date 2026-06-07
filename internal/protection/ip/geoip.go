package ip

import (
	"net"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/oschwald/maxminddb-golang"
)

type GeoIPPolicy struct {
	enabled bool
	blocked map[string]struct{}
	ranges  []countryRange
	reader  *maxminddb.Reader
}

type countryRange struct {
	country string
	network *net.IPNet
}

type GeoIPLocation struct {
	CountryCode string
	CountryName string
	Continent   string
	City        string
	Region      string
	RegionCode  string
	Latitude    float64
	Longitude   float64
	Accuracy    uint16
	TimeZone    string
	ASN         uint
	ASNOrg      string
	Source      string
}

type geoIPRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	City                         struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
		TimeZone       string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

func NewGeoIPPolicy(cfg config.GeoIPConfig) (*GeoIPPolicy, error) {
	policy := &GeoIPPolicy{
		enabled: cfg.Enabled,
		blocked: map[string]struct{}{},
	}
	for _, country := range cfg.BlockedCountries {
		country = strings.ToUpper(strings.TrimSpace(country))
		if country != "" {
			policy.blocked[country] = struct{}{}
		}
	}
	for country, cidrs := range cfg.CountryCIDRs {
		country = strings.ToUpper(strings.TrimSpace(country))
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}
			policy.ranges = append(policy.ranges, countryRange{country: country, network: network})
		}
	}
	if strings.TrimSpace(cfg.Database) != "" {
		reader, err := maxminddb.Open(cfg.Database)
		if err != nil {
			return nil, err
		}
		policy.reader = reader
	}
	return policy, nil
}

func (p *GeoIPPolicy) Country(clientIP string) string {
	return p.Lookup(clientIP).CountryCode
}

func (p *GeoIPPolicy) Lookup(clientIP string) GeoIPLocation {
	location := GeoIPLocation{}
	if p == nil {
		return location
	}
	parsed := net.ParseIP(clientIP)
	if parsed == nil {
		return location
	}
	if country := p.countryFromCIDR(parsed); country != "" {
		location.CountryCode = country
		location.Source = "cidr"
	}
	if p.reader == nil {
		return location
	}
	var record geoIPRecord
	if err := p.reader.Lookup(parsed, &record); err != nil {
		return location
	}
	countryCode := normalizeCountry(record.Country.ISOCode)
	countryName := localizedName(record.Country.Names)
	if countryCode == "" {
		countryCode = normalizeCountry(record.RegisteredCountry.ISOCode)
		countryName = localizedName(record.RegisteredCountry.Names)
	}
	if location.CountryCode == "" {
		location.CountryCode = countryCode
		location.Source = "mmdb"
	}
	location.CountryName = countryName
	location.Continent = strings.ToUpper(strings.TrimSpace(record.Continent.Code))
	location.City = localizedName(record.City.Names)
	if len(record.Subdivisions) > 0 {
		location.Region = localizedName(record.Subdivisions[0].Names)
		location.RegionCode = strings.ToUpper(strings.TrimSpace(record.Subdivisions[0].ISOCode))
	}
	location.Latitude = record.Location.Latitude
	location.Longitude = record.Location.Longitude
	location.Accuracy = record.Location.AccuracyRadius
	location.TimeZone = record.Location.TimeZone
	location.ASN = record.AutonomousSystemNumber
	location.ASNOrg = record.AutonomousSystemOrganization
	if location.Source == "" && (location.CountryCode != "" || location.City != "" || location.Region != "" || location.Latitude != 0 || location.Longitude != 0 || location.ASN != 0) {
		location.Source = "mmdb"
	}
	return location
}

func (p *GeoIPPolicy) Close() error {
	if p == nil || p.reader == nil {
		return nil
	}
	return p.reader.Close()
}

func (p *GeoIPPolicy) Blocked(clientIP string) bool {
	if p == nil || !p.enabled || len(p.blocked) == 0 {
		return false
	}
	country := p.Country(clientIP)
	if country == "" {
		return false
	}
	_, blocked := p.blocked[country]
	return blocked
}

func (p *GeoIPPolicy) countryFromCIDR(ip net.IP) string {
	for _, item := range p.ranges {
		if item.network.Contains(ip) {
			return item.country
		}
	}
	return ""
}

func (l GeoIPLocation) Metadata() map[string]any {
	metadata := map[string]any{}
	addString(metadata, "country_code", l.CountryCode)
	addString(metadata, "country_name", l.CountryName)
	addString(metadata, "continent", l.Continent)
	addString(metadata, "city", l.City)
	addString(metadata, "region", l.Region)
	addString(metadata, "region_code", l.RegionCode)
	if l.Latitude != 0 || l.Longitude != 0 {
		metadata["lat"] = l.Latitude
		metadata["lon"] = l.Longitude
		metadata["latitude"] = l.Latitude
		metadata["longitude"] = l.Longitude
	}
	if l.Accuracy > 0 {
		metadata["accuracy_radius"] = l.Accuracy
	}
	addString(metadata, "time_zone", l.TimeZone)
	if l.ASN > 0 {
		metadata["asn"] = l.ASN
	}
	addString(metadata, "asn_org", l.ASNOrg)
	addString(metadata, "source", l.Source)
	return metadata
}

func normalizeCountry(country string) string {
	return strings.ToUpper(strings.TrimSpace(country))
}

func localizedName(names map[string]string) string {
	if len(names) == 0 {
		return ""
	}
	for _, key := range []string{"zh-CN", "zh", "en"} {
		if value := strings.TrimSpace(names[key]); value != "" {
			return value
		}
	}
	for _, value := range names {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func addString(metadata map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		metadata[key] = strings.TrimSpace(value)
	}
}
