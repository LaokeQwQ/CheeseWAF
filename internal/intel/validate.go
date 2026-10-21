package intel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

// Errors returned by validation, fetching, trust, and compilation. Callers can
// use errors.Is to distinguish policy rejection from transport failures.
var (
	ErrInvalid                = errors.New("intel: invalid input")
	ErrUnsafeURL              = errors.New("intel: unsafe URL")
	ErrResponseTooLarge       = errors.New("intel: response exceeds size limit")
	ErrUnsupportedContentType = errors.New("intel: unsupported content type")
	ErrTooManyRedirects       = errors.New("intel: too many redirects")
	ErrQuarantined            = errors.New("intel: source quarantined")
	ErrBroadRule              = errors.New("intel: rule is too broad")
	ErrNoSafeRule             = errors.New("intel: no safe minimal rule available")
)

const (
	MaxExtractionCVEIDs       = 32
	MaxExtractionProducts     = 16
	MaxExtractionVersions     = 32
	MaxExtractionParameters   = 32
	MaxExtractionMarkers      = 32
	MaxExtractionReferences   = 32
	MaxExtractionStatusCodes  = 16
	MaxRulePatternBytes       = 2048
	MaxRuleJSONBytes          = 64 << 10
	MaxCandidateIDBytes       = 128
	MaxCandidateTTL           = 90 * 24 * time.Hour
	maxScopePathBytes         = 512
	maxExtractionNameBytes    = 128
	maxExtractionMarkerBytes  = 256
	maxExtractionURLBytes     = 2048
	maxSourceETagBytes        = 512
	maxSourceLastModifiedSize = 128
)

var (
	cvePattern        = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)
	parameterPattern  = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]{1,128}$`)
	headerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	safeIDPattern     = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)

	// referenceURLPolicy allows section fragments, which vendor advisories use.
	referenceURLPolicy = netguard.URLPolicy{
		Purpose:        "reference",
		HostPurpose:    "reference",
		AllowedSchemes: []string{"http", "https"},
		AllowFragment:  true,
	}
	sourceURLPolicy = netguard.URLPolicy{
		Purpose:        "intel source",
		HostPurpose:    "intel source",
		AllowedSchemes: []string{"http", "https"},
	}
)

var supportedMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodPatch:   {},
	http.MethodDelete:  {},
	http.MethodOptions: {},
}

var benignCorpus = []string{
	"/index.html",
	"hello world",
	"<html><body>ok</body></html>",
}

// ValidateReferenceURL enforces the reference URL policy: http(s) only, no
// credentials, public literal IPs only.
func ValidateReferenceURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%w: reference URL is empty", ErrInvalid)
	}
	if len(raw) > maxExtractionURLBytes {
		return fmt.Errorf("%w: reference URL exceeds %d bytes", ErrInvalid, maxExtractionURLBytes)
	}
	if _, err := netguard.ValidateURL(raw, referenceURLPolicy); err != nil {
		return fmt.Errorf("%w: reference URL %q: %v", ErrInvalid, raw, err)
	}
	return nil
}

// ValidateSource validates a source registration. Sources that are not manual
// must carry a fetchable URL.
func ValidateSource(source Source) error {
	if !safeIDPattern.MatchString(strings.TrimSpace(source.ID)) {
		return fmt.Errorf("%w: source id must match %s", ErrInvalid, safeIDPattern)
	}
	switch strings.ToLower(strings.TrimSpace(source.Type)) {
	case "rss", "atom", "api", "url", "manual":
	default:
		return fmt.Errorf("%w: source type must be rss, atom, api, url, or manual", ErrInvalid)
	}
	if trust := strings.TrimSpace(string(source.Trust)); trust != "" && !source.Trust.Valid() {
		return fmt.Errorf("%w: source trust must be official, vendor, community, or unknown", ErrInvalid)
	}
	if len(source.ETag) > maxSourceETagBytes {
		return fmt.Errorf("%w: source etag exceeds %d bytes", ErrInvalid, maxSourceETagBytes)
	}
	if len(source.LastModified) > maxSourceLastModifiedSize {
		return fmt.Errorf("%w: source last_modified exceeds %d bytes", ErrInvalid, maxSourceLastModifiedSize)
	}
	if strings.EqualFold(strings.TrimSpace(source.Type), "manual") && strings.TrimSpace(source.URL) == "" {
		return nil
	}
	raw := strings.TrimSpace(source.URL)
	if raw == "" {
		return fmt.Errorf("%w: source url is required", ErrInvalid)
	}
	if len(raw) > maxExtractionURLBytes {
		return fmt.Errorf("%w: source url exceeds %d bytes", ErrInvalid, maxExtractionURLBytes)
	}
	if _, err := netguard.ValidateURL(raw, sourceURLPolicy); err != nil {
		return fmt.Errorf("%w: source url %q: %v", ErrInvalid, raw, err)
	}
	return nil
}

// ValidateExtraction enforces required fields, bounds, and enums on extractor
// output. It does not require a compilable shape; that is the compiler's job.
func ValidateExtraction(extraction Extraction) error {
	if !(extraction.Confidence > 0 && extraction.Confidence <= 1) {
		return fmt.Errorf("%w: confidence must be greater than 0 and at most 1", ErrInvalid)
	}
	if len(extraction.CVEIDs) > MaxExtractionCVEIDs {
		return fmt.Errorf("%w: too many CVE ids: %d", ErrInvalid, len(extraction.CVEIDs))
	}
	seenCVE := make(map[string]struct{}, len(extraction.CVEIDs))
	for _, cve := range extraction.CVEIDs {
		cve = strings.TrimSpace(cve)
		if !cvePattern.MatchString(cve) {
			return fmt.Errorf("%w: invalid CVE id %q", ErrInvalid, cve)
		}
		key := strings.ToUpper(cve)
		if _, exists := seenCVE[key]; exists {
			return fmt.Errorf("%w: duplicate CVE id %q", ErrInvalid, cve)
		}
		seenCVE[key] = struct{}{}
	}
	if len(extraction.Products) > MaxExtractionProducts {
		return fmt.Errorf("%w: too many products: %d", ErrInvalid, len(extraction.Products))
	}
	for _, product := range extraction.Products {
		if err := validateShortText("product", product, maxExtractionNameBytes); err != nil {
			return err
		}
	}
	if len(extraction.AffectedVersions) > MaxExtractionVersions {
		return fmt.Errorf("%w: too many affected versions: %d", ErrInvalid, len(extraction.AffectedVersions))
	}
	for _, version := range extraction.AffectedVersions {
		if err := validateShortText("affected version", version, maxExtractionNameBytes); err != nil {
			return err
		}
	}
	if err := validateRequestShape(extraction.Request); err != nil {
		return err
	}
	if err := validateResponseEvidence(extraction.Response); err != nil {
		return err
	}
	if len(extraction.References) > MaxExtractionReferences {
		return fmt.Errorf("%w: too many references: %d", ErrInvalid, len(extraction.References))
	}
	for _, reference := range extraction.References {
		if err := ValidateReferenceURL(reference); err != nil {
			return err
		}
	}
	return nil
}

func validateRequestShape(shape RequestShape) error {
	if method := strings.TrimSpace(shape.Method); method != "" {
		if _, ok := supportedMethods[strings.ToUpper(method)]; !ok {
			return fmt.Errorf("%w: unsupported request method %q", ErrInvalid, method)
		}
	}
	if shape.Path != "" {
		if err := validatePathPrefix(shape.Path, "request path"); err != nil {
			return err
		}
	}
	if shape.ContentType != "" {
		if err := validateShortText("content type", shape.ContentType, maxExtractionNameBytes); err != nil {
			return err
		}
	}
	if len(shape.ParameterNames) > MaxExtractionParameters {
		return fmt.Errorf("%w: too many parameter names: %d", ErrInvalid, len(shape.ParameterNames))
	}
	for _, name := range shape.ParameterNames {
		if !parameterPattern.MatchString(name) {
			return fmt.Errorf("%w: invalid parameter name %q", ErrInvalid, name)
		}
	}
	if len(shape.Markers) > MaxExtractionMarkers {
		return fmt.Errorf("%w: too many request markers: %d", ErrInvalid, len(shape.Markers))
	}
	for _, marker := range shape.Markers {
		if err := validateMarker("request marker", marker); err != nil {
			return err
		}
	}
	if shape.SessionParameter != "" && !parameterPattern.MatchString(shape.SessionParameter) {
		return fmt.Errorf("%w: invalid session parameter %q", ErrInvalid, shape.SessionParameter)
	}
	return nil
}

func validateResponseEvidence(evidence ResponseEvidence) error {
	if len(evidence.StatusCodes) > MaxExtractionStatusCodes {
		return fmt.Errorf("%w: too many status codes: %d", ErrInvalid, len(evidence.StatusCodes))
	}
	for _, code := range evidence.StatusCodes {
		if code < 100 || code > 599 {
			return fmt.Errorf("%w: status code %d is out of range", ErrInvalid, code)
		}
	}
	if len(evidence.HeaderNames) > MaxExtractionMarkers {
		return fmt.Errorf("%w: too many header names: %d", ErrInvalid, len(evidence.HeaderNames))
	}
	for _, name := range evidence.HeaderNames {
		if !headerNamePattern.MatchString(strings.TrimSpace(name)) {
			return fmt.Errorf("%w: invalid header name %q", ErrInvalid, name)
		}
	}
	if len(evidence.BodyMarkers) > MaxExtractionMarkers {
		return fmt.Errorf("%w: too many body markers: %d", ErrInvalid, len(evidence.BodyMarkers))
	}
	for _, marker := range evidence.BodyMarkers {
		if err := validateMarker("body marker", marker); err != nil {
			return err
		}
	}
	return nil
}

func validateShortText(label, value string, max int) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalid, label)
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, max)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalid, label)
		}
	}
	return nil
}

func validateMarker(label, marker string) error {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalid, label)
	}
	if len(marker) > maxExtractionMarkerBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, maxExtractionMarkerBytes)
	}
	if !utf8.ValidString(marker) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalid, label)
	}
	for _, r := range marker {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalid, label)
		}
	}
	return nil
}

func validatePathPrefix(path, label string) error {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: %s must start with /", ErrInvalid, label)
	}
	if len(path) > maxScopePathBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, maxScopePathBytes)
	}
	if strings.ContainsAny(path, "?#") || strings.ContainsAny(path, " \t\r\n") {
		return fmt.Errorf("%w: %s must not contain a query, fragment, or whitespace", ErrInvalid, label)
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalid, label)
		}
	}
	return nil
}

// Validate checks the scope. A globally scoped candidate is always rejected.
func (s Scope) Validate() error {
	if s.IsGlobal() {
		return fmt.Errorf("%w: rule scope must name a single site", ErrInvalid)
	}
	if !safeIDPattern.MatchString(strings.TrimSpace(s.SiteID)) {
		return fmt.Errorf("%w: scope site id must match %s", ErrInvalid, safeIDPattern)
	}
	if s.PathPrefix != "" {
		if err := validatePathPrefix(s.PathPrefix, "scope path prefix"); err != nil {
			return err
		}
		if strings.TrimSpace(s.PathPrefix) == "/" {
			return fmt.Errorf("%w: scope path prefix must be narrower than /", ErrInvalid)
		}
	}
	if len(s.Methods) > 8 {
		return fmt.Errorf("%w: too many scope methods: %d", ErrInvalid, len(s.Methods))
	}
	seen := make(map[string]struct{}, len(s.Methods))
	for _, method := range s.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if _, ok := supportedMethods[method]; !ok {
			return fmt.Errorf("%w: unsupported scope method %q", ErrInvalid, method)
		}
		if _, exists := seen[method]; exists {
			return fmt.Errorf("%w: duplicate scope method %q", ErrInvalid, method)
		}
		seen[method] = struct{}{}
	}
	return nil
}

// ValidatePatternBroadness rejects regexes that would match arbitrary traffic.
// It combines structural checks, an empty-string match check, and a benign
// negative corpus so a generated rule must retain real literal specificity.
func ValidatePatternBroadness(pattern string) error {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return fmt.Errorf("%w: pattern is empty", ErrBroadRule)
	}
	if len(trimmed) > MaxRulePatternBytes {
		return fmt.Errorf("%w: pattern exceeds %d bytes", ErrBroadRule, MaxRulePatternBytes)
	}
	if strings.Contains(trimmed, "(?s)") && strings.Contains(trimmed, ".*") {
		return fmt.Errorf("%w: dotall wildcard patterns are not allowed", ErrBroadRule)
	}
	if hasUnboundedWildcard(trimmed) {
		return fmt.Errorf("%w: unbounded wildcard repeats are not allowed", ErrBroadRule)
	}
	skeleton := strings.Map(func(r rune) rune {
		if strings.ContainsRune(`.*+?()[]{}^$|\ `, r) {
			return -1
		}
		return r
	}, trimmed)
	if strings.TrimSpace(skeleton) == "" {
		return fmt.Errorf("%w: pattern has no literal content", ErrBroadRule)
	}
	re, err := regexp.Compile(trimmed)
	if err != nil {
		return fmt.Errorf("%w: pattern does not compile: %v", ErrInvalid, err)
	}
	if re.MatchString("") {
		return fmt.Errorf("%w: pattern matches the empty string", ErrBroadRule)
	}
	matched := 0
	for _, sample := range benignCorpus {
		if re.MatchString(sample) {
			matched++
		}
	}
	if matched == len(benignCorpus) {
		return fmt.Errorf("%w: pattern matches unrelated benign traffic", ErrBroadRule)
	}
	return nil
}

// hasUnboundedWildcard reports whether a dot wildcard is repeated without an
// upper bound (.*, .+, .{n,}). Escaped dots and dots inside character classes
// are literals and do not count.
func hasUnboundedWildcard(pattern string) bool {
	inClass := false
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '\\':
			index++
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '.':
			if inClass {
				continue
			}
			next := index + 1
			if next < len(pattern) && (pattern[next] == '*' || pattern[next] == '+') {
				return true
			}
			if next < len(pattern) && pattern[next] == '{' {
				cursor := next + 1
				digits := 0
				for cursor < len(pattern) && pattern[cursor] >= '0' && pattern[cursor] <= '9' {
					cursor++
					digits++
				}
				if digits > 0 && cursor < len(pattern) && pattern[cursor] == ',' {
					cursor++
					if cursor < len(pattern) && pattern[cursor] == '}' {
						return true
					}
				}
			}
		}
	}
	return false
}

// ValidateCompiledRule validates a generated rule and its scope. Generated
// rules must start disabled and must satisfy the broadness guard.
func ValidateCompiledRule(compiled CompiledRule) error {
	if err := compiled.Scope.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(compiled.Rule.ID) == "" {
		return fmt.Errorf("%w: rule id is required", ErrInvalid)
	}
	if !safeIDPattern.MatchString(strings.TrimSpace(compiled.Rule.ID)) {
		return fmt.Errorf("%w: rule id must match %s", ErrInvalid, safeIDPattern)
	}
	if len(compiled.Rule.Pattern) > MaxRulePatternBytes {
		return fmt.Errorf("%w: pattern exceeds %d bytes", ErrInvalid, MaxRulePatternBytes)
	}
	if compiled.Rule.Enabled {
		return fmt.Errorf("%w: generated rules must start disabled", ErrInvalid)
	}
	if err := ValidatePatternBroadness(compiled.Rule.Pattern); err != nil {
		return err
	}
	if err := config.ValidateCustomRule(compiled.Rule); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	switch strings.ToLower(strings.TrimSpace(compiled.Rule.Action)) {
	case ActionLog, ActionChallenge, ActionBlock:
	default:
		return fmt.Errorf("%w: rule action must be log, challenge, or block", ErrInvalid)
	}
	return nil
}

// ValidateCandidate enforces the candidate contract, including TTL, scope,
// action enum, and the rule that block requires explicit human approval.
func ValidateCandidate(candidate Candidate) error {
	if !safeIDPattern.MatchString(strings.TrimSpace(candidate.ID)) {
		return fmt.Errorf("%w: candidate id must match %s", ErrInvalid, safeIDPattern)
	}
	if strings.TrimSpace(candidate.ItemID) == "" {
		return fmt.Errorf("%w: candidate item id is required", ErrInvalid)
	}
	if strings.TrimSpace(candidate.SiteID) == "" {
		return fmt.Errorf("%w: candidate site id is required", ErrInvalid)
	}
	if !candidate.State.Valid() {
		return fmt.Errorf("%w: invalid candidate state %q", ErrInvalid, candidate.State)
	}
	if !(candidate.Confidence > 0 && candidate.Confidence <= 1) {
		return fmt.Errorf("%w: confidence must be greater than 0 and at most 1", ErrInvalid)
	}
	if candidate.TTL <= 0 {
		return fmt.Errorf("%w: candidate TTL must be greater than zero", ErrInvalid)
	}
	if candidate.TTL > MaxCandidateTTL {
		return fmt.Errorf("%w: candidate TTL exceeds %s", ErrInvalid, MaxCandidateTTL)
	}
	if candidate.CreatedAt.IsZero() {
		return fmt.Errorf("%w: candidate created_at is required", ErrInvalid)
	}
	if strings.TrimSpace(candidate.Provenance.SourceID) == "" {
		return fmt.Errorf("%w: candidate provenance source id is required", ErrInvalid)
	}
	if !safeIDPattern.MatchString(strings.TrimSpace(candidate.Provenance.SourceID)) {
		return fmt.Errorf("%w: provenance source id must match %s", ErrInvalid, safeIDPattern)
	}
	if !candidate.Provenance.SourceTrust.Valid() || candidate.Provenance.SourceTrust == TrustUnknown {
		return fmt.Errorf("%w: candidate provenance requires a trusted source", ErrInvalid)
	}
	if candidate.Provenance.ItemID != "" && candidate.Provenance.ItemID != candidate.ItemID {
		return fmt.Errorf("%w: provenance item id does not match candidate item id", ErrInvalid)
	}
	action := strings.ToLower(strings.TrimSpace(candidate.Action))
	switch action {
	case ActionLog, ActionChallenge, ActionBlock:
	default:
		return fmt.Errorf("%w: candidate action must be log, challenge, or block", ErrInvalid)
	}
	if action == ActionBlock {
		if !candidate.Provenance.Approved {
			return fmt.Errorf("%w: block candidates require explicit human approval", ErrInvalid)
		}
		if candidate.State != CandidateCanary && candidate.State != CandidateActive {
			return fmt.Errorf("%w: block candidates must be canary or active", ErrInvalid)
		}
	}
	if len(candidate.RuleJSON) == 0 || len(candidate.RuleJSON) > MaxRuleJSONBytes {
		return fmt.Errorf("%w: candidate rule_json is empty or exceeds %d bytes", ErrInvalid, MaxRuleJSONBytes)
	}
	compiled, err := DecodeCompiledRule([]byte(candidate.RuleJSON))
	if err != nil {
		return err
	}
	if strings.TrimSpace(compiled.Scope.SiteID) != strings.TrimSpace(candidate.SiteID) {
		return fmt.Errorf("%w: rule scope site does not match candidate site", ErrInvalid)
	}
	if strings.ToLower(strings.TrimSpace(compiled.Rule.Action)) != action {
		return fmt.Errorf("%w: rule action does not match candidate action", ErrInvalid)
	}
	return nil
}

// DecodeExtraction decodes a single structured extraction object and validates
// it. Unknown fields are tolerated so extractors can add metadata.
func DecodeExtraction(data []byte) (Extraction, error) {
	var extraction Extraction
	if err := decodeSingleJSON(data, &extraction); err != nil {
		return Extraction{}, err
	}
	if err := ValidateExtraction(extraction); err != nil {
		return Extraction{}, err
	}
	return extraction, nil
}

// DecodeCandidate decodes and validates a candidate.
func DecodeCandidate(data []byte) (Candidate, error) {
	var candidate Candidate
	if err := decodeSingleJSON(data, &candidate); err != nil {
		return Candidate{}, err
	}
	if err := ValidateCandidate(candidate); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

// DecodeCompiledRule decodes and validates a compiled rule payload.
func DecodeCompiledRule(data []byte) (CompiledRule, error) {
	var compiled CompiledRule
	if err := decodeSingleJSON(data, &compiled); err != nil {
		return CompiledRule{}, err
	}
	if err := ValidateCompiledRule(compiled); err != nil {
		return CompiledRule{}, err
	}
	return compiled, nil
}

func decodeSingleJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode json: %v", ErrInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: json contains more than one value", ErrInvalid)
		}
		return fmt.Errorf("%w: trailing json: %v", ErrInvalid, err)
	}
	return nil
}
