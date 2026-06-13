package ip

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/oschwald/maxminddb-golang"
)

type GeoIPPolicy struct {
	enabled bool
	blocked map[string]struct{}
	ranges  []countryRange
	precise []precisionRange
	reader  *maxminddb.Reader
}

type countryRange struct {
	country string
	network *net.IPNet
}

type precisionRange struct {
	location GeoIPLocation
	network  *net.IPNet
	ones     int
}

type GeoIPLocation struct {
	CountryCode  string
	CountryName  string
	Continent    string
	City         string
	Region       string
	RegionCode   string
	District     string
	DistrictCode string
	Street       string
	StreetCode   string
	Latitude     float64
	Longitude    float64
	Accuracy     uint16
	TimeZone     string
	ASN          uint
	ASNOrg       string
	Source       string
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

type precisionDatabase struct {
	Records []precisionRecord `json:"records"`
}

type precisionRecord struct {
	CIDR         string  `json:"cidr"`
	IP           string  `json:"ip"`
	CountryCode  string  `json:"country_code"`
	CountryName  string  `json:"country_name"`
	Continent    string  `json:"continent"`
	City         string  `json:"city"`
	Region       string  `json:"region"`
	RegionCode   string  `json:"region_code"`
	District     string  `json:"district"`
	DistrictCode string  `json:"district_code"`
	Street       string  `json:"street"`
	StreetCode   string  `json:"street_code"`
	Latitude     float64 `json:"lat"`
	Longitude    float64 `json:"lon"`
	Accuracy     uint16  `json:"accuracy_radius"`
	TimeZone     string  `json:"time_zone"`
	ASN          uint    `json:"asn"`
	ASNOrg       string  `json:"asn_org"`
	Source       string  `json:"source"`
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
	if strings.TrimSpace(cfg.PrecisionDatabase) != "" {
		ranges, err := loadPrecisionDatabase(cfg.PrecisionDatabase)
		if err != nil {
			if os.IsNotExist(err) {
				return policy, nil
			}
			return nil, err
		}
		policy.precise = ranges
	}
	if strings.TrimSpace(cfg.Database) != "" {
		reader, err := maxminddb.Open(cfg.Database)
		if err != nil {
			if os.IsNotExist(err) {
				return policy, nil
			}
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
	precise, hasPrecise := p.precisionLocation(parsed)
	if p.reader == nil {
		if hasPrecise {
			return mergeLocation(location, precise)
		}
		return location
	}
	var record geoIPRecord
	if err := p.reader.Lookup(parsed, &record); err != nil {
		if hasPrecise {
			return mergeLocation(location, precise)
		}
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
		if len(record.Subdivisions) > 1 {
			last := record.Subdivisions[len(record.Subdivisions)-1]
			location.District = localizedName(last.Names)
			location.DistrictCode = strings.ToUpper(strings.TrimSpace(last.ISOCode))
		}
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
	if hasPrecise {
		location = mergeLocation(location, precise)
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

func (p *GeoIPPolicy) precisionLocation(ip net.IP) (GeoIPLocation, bool) {
	matches := make([]precisionRange, 0, 2)
	for _, item := range p.precise {
		if item.network.Contains(ip) {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return GeoIPLocation{}, false
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].ones < matches[j].ones
	})
	location := GeoIPLocation{}
	for _, item := range matches {
		location = mergeLocation(location, item.location)
	}
	return location, true
}

func (l GeoIPLocation) Metadata() map[string]any {
	metadata := map[string]any{}
	addString(metadata, "country_code", l.CountryCode)
	addString(metadata, "country_name", l.CountryName)
	addString(metadata, "continent", l.Continent)
	addString(metadata, "city", l.City)
	addString(metadata, "region", l.Region)
	addString(metadata, "region_code", l.RegionCode)
	addString(metadata, "district", l.District)
	addString(metadata, "district_code", l.DistrictCode)
	addString(metadata, "street", l.Street)
	addString(metadata, "street_code", l.StreetCode)
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

func loadPrecisionDatabase(path string) ([]precisionRange, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []precisionRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		var wrapped precisionDatabase
		if wrappedErr := json.Unmarshal(raw, &wrapped); wrappedErr != nil {
			return nil, err
		}
		records = wrapped.Records
	}
	ranges := make([]precisionRange, 0, len(records))
	for _, record := range records {
		network, ones, ok := precisionNetwork(record)
		if !ok {
			continue
		}
		location := GeoIPLocation{
			CountryCode:  normalizeCountry(record.CountryCode),
			CountryName:  strings.TrimSpace(record.CountryName),
			Continent:    strings.ToUpper(strings.TrimSpace(record.Continent)),
			City:         strings.TrimSpace(record.City),
			Region:       strings.TrimSpace(record.Region),
			RegionCode:   strings.ToUpper(strings.TrimSpace(record.RegionCode)),
			District:     strings.TrimSpace(record.District),
			DistrictCode: strings.TrimSpace(record.DistrictCode),
			Street:       strings.TrimSpace(record.Street),
			StreetCode:   strings.TrimSpace(record.StreetCode),
			Latitude:     record.Latitude,
			Longitude:    record.Longitude,
			Accuracy:     record.Accuracy,
			TimeZone:     strings.TrimSpace(record.TimeZone),
			ASN:          record.ASN,
			ASNOrg:       strings.TrimSpace(record.ASNOrg),
			Source:       firstNonEmpty(strings.TrimSpace(record.Source), "precision-json"),
		}
		ranges = append(ranges, precisionRange{network: network, ones: ones, location: location})
	}
	return ranges, nil
}

func precisionNetwork(record precisionRecord) (*net.IPNet, int, bool) {
	if cidr := strings.TrimSpace(record.CIDR); cidr != "" {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, 0, false
		}
		ones, _ := network.Mask.Size()
		return network, ones, true
	}
	parsed := net.ParseIP(strings.TrimSpace(record.IP))
	if parsed == nil {
		return nil, 0, false
	}
	if parsed.To4() != nil {
		return &net.IPNet{IP: parsed.Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)}, 32, true
	}
	return &net.IPNet{IP: parsed.Mask(net.CIDRMask(128, 128)), Mask: net.CIDRMask(128, 128)}, 128, true
}

func mergeLocation(base, precise GeoIPLocation) GeoIPLocation {
	out := base
	out.CountryCode = firstNonEmpty(precise.CountryCode, out.CountryCode)
	out.CountryName = firstNonEmpty(precise.CountryName, out.CountryName)
	out.Continent = firstNonEmpty(precise.Continent, out.Continent)
	out.City = firstNonEmpty(precise.City, out.City)
	out.Region = firstNonEmpty(precise.Region, out.Region)
	out.RegionCode = firstNonEmpty(precise.RegionCode, out.RegionCode)
	out.District = firstNonEmpty(precise.District, out.District)
	out.DistrictCode = firstNonEmpty(precise.DistrictCode, out.DistrictCode)
	out.Street = firstNonEmpty(precise.Street, out.Street)
	out.StreetCode = firstNonEmpty(precise.StreetCode, out.StreetCode)
	if precise.Latitude != 0 || precise.Longitude != 0 {
		out.Latitude = precise.Latitude
		out.Longitude = precise.Longitude
	}
	if precise.Accuracy > 0 {
		out.Accuracy = precise.Accuracy
	}
	out.TimeZone = firstNonEmpty(precise.TimeZone, out.TimeZone)
	if precise.ASN > 0 {
		out.ASN = precise.ASN
	}
	out.ASNOrg = firstNonEmpty(precise.ASNOrg, out.ASNOrg)
	out.Source = firstNonEmpty(precise.Source, out.Source)
	return out
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
