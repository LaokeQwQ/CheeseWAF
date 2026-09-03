package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// HTTPTransactionVersion is the current wire format version.
const HTTPTransactionVersion = "http-transaction/v1"

// MaxHTTPSnapshotBodyBytes bounds each captured request and response body.
const MaxHTTPSnapshotBodyBytes = 1 << 20

const (
	maxHTTPSnapshotHeaders = 128
	maxHTTPSnapshotURI     = 8192
	maxHTTPSnapshotField   = 4096
)

// HTTPHeader is deliberately a slice entry (rather than a map) so duplicate
// header names can be detected and rejected at the trust boundary.
type HTTPHeader struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type HTTPRequest struct {
	Method     string       `json:"method"`
	Target     string       `json:"target"`
	Protocol   string       `json:"protocol"`
	Headers    []HTTPHeader `json:"headers,omitempty"`
	Body       []byte       `json:"body,omitempty"`
	BodySHA256 string       `json:"body_sha256"`
	BodyBytes  int64        `json:"body_bytes"`
}

type HTTPResponse struct {
	StatusCode int          `json:"status_code"`
	Protocol   string       `json:"protocol"`
	Headers    []HTTPHeader `json:"headers,omitempty"`
	Body       []byte       `json:"body,omitempty"`
	BodySHA256 string       `json:"body_sha256"`
	BodyBytes  int64        `json:"body_bytes"`
}

// OracleLabel is independent ground truth. It must never be populated from a
// WAF decision, score, or observed detector output.
type OracleLabel struct {
	Label         string `json:"label"`
	Category      string `json:"category,omitempty"`
	OracleType    string `json:"oracle_type"`
	OracleVersion string `json:"oracle_version"`
	AssertionID   string `json:"assertion_id,omitempty"`
}

// HTTPTransaction is a bounded, versioned request/response observation with
// an independently supplied oracle label and replay provenance.
type HTTPTransaction struct {
	Version             string       `json:"version"`
	Request             HTTPRequest  `json:"request"`
	Response            HTTPResponse `json:"response"`
	ExpectedOracleLabel OracleLabel  `json:"expected_oracle_label"`
	Deployment          string       `json:"deployment"`
	Provenance          string       `json:"provenance"`
	Source              string       `json:"source"`
	Site                string       `json:"site"`
	Session             string       `json:"session"`
	Timestamp           time.Time    `json:"timestamp"`
	Hash                string       `json:"hash"`
	Seed                string       `json:"seed"`
	Run                 string       `json:"run"`
	Assertion           string       `json:"assertion,omitempty"`
}

var emailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)

// secretPattern recognizes both query/form assignments and quoted object
// keys. It intentionally rejects the field before inspecting its value: a
// snapshot must never retain a credential merely because the value happens to
// be empty, encoded, or nested in a JSON document.
var secretPattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])['"]?(?:authorization|cookie|api[_-]?key|access[_-]?token|secret|password|passwd|token|bearer|private[_-]?key)['"]?\s*[:=]`)

// derivedOraclePattern is applied only to oracle metadata, not request
// payloads. Attack payloads are allowed to contain words such as "blocked";
// oracle fields must not be labels copied from a detector or WAF decision.
var derivedOraclePattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:waf|firewall|detector|blocked|allowed|decision|detected|score|result)(?:$|[^a-z0-9])`)
var observedEvidencePattern = regexp.MustCompile(`(?i)(repaired|observed[_ -]?waf|waf[_ -]?(decision|result|output)|detector[_ -]?(decision|result|output))`)

var observedHeaderPattern = regexp.MustCompile(`(?i)(?:^|[-_])(waf|firewall|detector|decision|score|blocked)(?:$|[-_])`)
var httpProtocolPattern = regexp.MustCompile(`^HTTP/[0-9]+(?:\.[0-9]+)?$`)

var forbiddenHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true,
	"set-cookie": true, "x-api-key": true, "x-auth-token": true,
}

// ValidateHTTPTransaction performs strict shape, provenance, body, and
// redaction checks before a transaction is used for blind evaluation.
func ValidateHTTPTransaction(tx HTTPTransaction) error {
	if tx.Version != HTTPTransactionVersion {
		return fmt.Errorf("unsupported transaction version %q", tx.Version)
	}
	for name, value := range map[string]string{"deployment": tx.Deployment, "provenance": tx.Provenance, "source": tx.Source, "site": tx.Site, "session": tx.Session, "seed": tx.Seed, "run": tx.Run} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
		if err := validateMetadataText(name, value); err != nil {
			return err
		}
		if observedEvidencePattern.MatchString(value) {
			return fmt.Errorf("%s contains repaired or observed-WAF evidence", name)
		}
	}
	if strings.TrimSpace(tx.Hash) == "" {
		return errors.New("hash is required")
	}
	if !isLowerHexSHA256(tx.Hash) {
		return errors.New("hash must be a 64-character lowercase SHA-256")
	}
	if tx.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if strings.TrimSpace(tx.ExpectedOracleLabel.Label) == "" {
		return errors.New("expected oracle label is required")
	}
	label := strings.ToLower(strings.TrimSpace(tx.ExpectedOracleLabel.Label))
	if label != "attack" && label != "benign" {
		return fmt.Errorf("unsupported oracle label %q", tx.ExpectedOracleLabel.Label)
	}
	if derivedOraclePattern.MatchString(tx.ExpectedOracleLabel.Label) {
		return errors.New("oracle label appears derived from detector output")
	}
	for name, value := range map[string]string{
		"oracle_category":     tx.ExpectedOracleLabel.Category,
		"oracle_assertion_id": tx.ExpectedOracleLabel.AssertionID,
		"assertion":           tx.Assertion,
	} {
		if strings.TrimSpace(value) != "" {
			if err := validateMetadataText(name, value); err != nil {
				return err
			}
			if observedEvidencePattern.MatchString(value) || derivedOraclePattern.MatchString(value) {
				return fmt.Errorf("%s contains detector-derived or repaired evidence", name)
			}
		}
	}
	for n, v := range map[string]string{"oracle_type": tx.ExpectedOracleLabel.OracleType, "oracle_version": tx.ExpectedOracleLabel.OracleVersion} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("expected oracle %s is required", n)
		}
		if err := validateMetadataText("expected_oracle_"+n, v); err != nil {
			return err
		}
		if observedEvidencePattern.MatchString(v) || derivedOraclePattern.MatchString(v) {
			return fmt.Errorf("expected oracle %s contains detector-derived or repaired evidence", n)
		}
	}
	if strings.TrimSpace(tx.Assertion) == "" {
		return errors.New("assertion is required")
	}
	if tx.Assertion != "" && tx.ExpectedOracleLabel.AssertionID != "" && tx.Assertion != tx.ExpectedOracleLabel.AssertionID {
		return errors.New("assertion and oracle assertion_id must match")
	}
	if err := validateRequest(tx.Request); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if err := validateResponse(tx.Response); err != nil {
		return fmt.Errorf("response: %w", err)
	}
	canonical, err := canonicalSHA256(tx)
	if err != nil {
		return err
	}
	if tx.Hash != canonical {
		return fmt.Errorf("hash does not match canonical transaction: got %s want %s", tx.Hash, canonical)
	}
	return nil
}

// ValidateHTTPTransactionSet enforces blind-set diversity and rejects
// duplicated observations before a set is admitted to evaluation.
func ValidateHTTPTransactionSet(txs []HTTPTransaction) error {
	if len(txs) == 0 {
		return errors.New("transaction set must not be empty")
	}
	deployments := make(map[string]map[string]bool)
	hashes := make(map[string]bool, len(txs))
	fingerprints := make(map[string]string, len(txs))
	groups := make(map[string]bool)
	for i, tx := range txs {
		if err := ValidateHTTPTransaction(tx); err != nil {
			return fmt.Errorf("transaction %d: %w", i, err)
		}
		if hashes[tx.Hash] {
			return fmt.Errorf("transaction %d duplicates hash %s", i, tx.Hash)
		}
		hashes[tx.Hash] = true
		fingerprint, err := HTTPTransactionFingerprint(tx)
		if err != nil {
			return fmt.Errorf("transaction %d fingerprint: %w", i, err)
		}
		// A request repeated by another deployment is still the same semantic
		// observation for corpus purposes. Keep the fingerprint global instead
		// of namespacing it by deployment/site; otherwise a caller could satisfy
		// the diversity gate by replaying identical rows into two containers.
		oracle := strings.ToLower(strings.TrimSpace(tx.ExpectedOracleLabel.Label)) + "\x00" + strings.ToLower(strings.TrimSpace(tx.ExpectedOracleLabel.Category))
		if previous, ok := fingerprints[fingerprint]; ok {
			if previous != oracle {
				return fmt.Errorf("transaction %d duplicates request fingerprint %s with conflicting oracle labels", i, fingerprint)
			}
			return fmt.Errorf("transaction %d duplicates request fingerprint %s", i, fingerprint)
		}
		fingerprints[fingerprint] = oracle
		dep := strings.TrimSpace(tx.Deployment)
		if deployments[dep] == nil {
			deployments[dep] = make(map[string]bool)
		}
		deployments[dep][strings.ToLower(strings.TrimSpace(tx.ExpectedOracleLabel.Label))] = true
		groups[dep+"\x00"+strings.TrimSpace(tx.Site)] = true
	}
	if len(deployments) < 2 {
		return errors.New("transaction set requires at least two deployments")
	}
	for deployment, labels := range deployments {
		if !labels["benign"] || !labels["attack"] {
			return fmt.Errorf("deployment %q must contain both benign and attack transactions", deployment)
		}
	}
	if len(groups) < 2 {
		return errors.New("transaction set requires at least two deployment/site groups")
	}
	return nil
}

// HTTPTransactionFingerprint identifies only the normalized request while
// excluding response, oracle labels, and run-specific provenance, assertion,
// and sealing hash fields. A request replayed with a different oracle label is
// therefore still a duplicate and must be handled as a governance conflict.
func HTTPTransactionFingerprint(tx HTTPTransaction) (string, error) {
	return transactionFingerprint(tx)
}

func transactionFingerprint(tx HTTPTransaction) (string, error) {
	// Duplicate identity is request-level: response bytes, deployment names,
	// capture runs and assertion IDs must not make a replayed request appear
	// new. Oracle labels are checked separately by ValidateHTTPTransactionSet.
	type canonicalHeader struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	}
	normalizeHeaders := func(in []HTTPHeader) []canonicalHeader {
		out := make([]canonicalHeader, 0, len(in))
		for _, h := range in {
			values := append([]string(nil), h.Values...)
			sort.Strings(values)
			out = append(out, canonicalHeader{
				Name:   strings.ToLower(strings.TrimSpace(h.Name)),
				Values: values,
			})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Name != out[j].Name {
				return out[i].Name < out[j].Name
			}
			return strings.Join(out[i].Values, "\x00") < strings.Join(out[j].Values, "\x00")
		})
		return out
	}
	requestOnly := struct {
		Version string `json:"version"`
		Request struct {
			Method     string            `json:"method"`
			Target     string            `json:"target"`
			Protocol   string            `json:"protocol"`
			Headers    []canonicalHeader `json:"headers,omitempty"`
			Body       []byte            `json:"body,omitempty"`
			BodySHA256 string            `json:"body_sha256"`
			BodyBytes  int64             `json:"body_bytes"`
		} `json:"request"`
	}{Version: tx.Version}
	requestOnly.Request.Method = strings.ToUpper(strings.TrimSpace(tx.Request.Method))
	requestOnly.Request.Target = normalizeTargetForFingerprint(tx.Request.Target)
	requestOnly.Request.Protocol = strings.ToUpper(strings.TrimSpace(tx.Request.Protocol))
	requestOnly.Request.Headers = normalizeHeaders(tx.Request.Headers)
	requestOnly.Request.Body = tx.Request.Body
	requestOnly.Request.BodySHA256 = tx.Request.BodySHA256
	requestOnly.Request.BodyBytes = tx.Request.BodyBytes
	b, err := json.Marshal(requestOnly)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NewHTTPTransaction fills body digests/lengths and seals the canonical hash.
// It does not bypass validation; callers should run ValidateHTTPTransaction
// after populating the required provenance and oracle fields.
func NewHTTPTransaction(tx HTTPTransaction) (HTTPTransaction, error) {
	tx.Version = firstNonEmpty(tx.Version, HTTPTransactionVersion)
	tx.Request.BodyBytes = int64(len(tx.Request.Body))
	rh := sha256.Sum256(tx.Request.Body)
	tx.Request.BodySHA256 = hex.EncodeToString(rh[:])
	tx.Response.BodyBytes = int64(len(tx.Response.Body))
	sh := sha256.Sum256(tx.Response.Body)
	tx.Response.BodySHA256 = hex.EncodeToString(sh[:])
	hash, err := CanonicalSHA256(tx)
	if err != nil {
		return HTTPTransaction{}, err
	}
	tx.Hash = hash
	return tx, nil
}

func validateRequest(r HTTPRequest) error {
	if err := validateHTTPToken("method", r.Method); err != nil {
		return err
	}
	if err := validateHTTPProtocol(r.Protocol); err != nil {
		return err
	}
	if strings.TrimSpace(r.Target) == "" {
		return errors.New("target is required")
	}
	if len(r.Target) > maxHTTPSnapshotURI {
		return errors.New("target exceeds size limit")
	}
	if err := validateMetadataText("target", r.Target); err != nil {
		return err
	}
	parsed, err := url.Parse(strings.TrimSpace(r.Target))
	if err != nil {
		return fmt.Errorf("target is not a valid URI: %w", err)
	}
	// A blind snapshot is replayed against an explicitly selected deployment.
	// An absolute or scheme-relative target could redirect evaluation to an
	// unrelated host, so the wire contract only admits relative targets.
	if parsed.IsAbs() || parsed.Host != "" || strings.HasPrefix(strings.TrimSpace(r.Target), "//") {
		return errors.New("target must be a relative request target")
	}
	if err := validateHeaders(r.Headers); err != nil {
		return err
	}
	return validateBody(r.Body, r.BodySHA256, r.BodyBytes)
}

func validateResponse(r HTTPResponse) error {
	if r.StatusCode < 100 || r.StatusCode > 599 {
		return errors.New("status_code is invalid")
	}
	if err := validateHTTPProtocol(r.Protocol); err != nil {
		return err
	}
	if err := validateHeaders(r.Headers); err != nil {
		return err
	}
	return validateBody(r.Body, r.BodySHA256, r.BodyBytes)
}

func validateHeaders(headers []HTTPHeader) error {
	if len(headers) > maxHTTPSnapshotHeaders {
		return errors.New("too many headers")
	}
	seen := make(map[string]bool, len(headers))
	for _, h := range headers {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			return errors.New("header name is required")
		}
		if err := validateHTTPHeaderName(h.Name); err != nil {
			return err
		}
		key := strings.ToLower(name)
		if seen[key] {
			return fmt.Errorf("duplicate header %q", name)
		}
		seen[key] = true
		if forbiddenHeaders[key] {
			return fmt.Errorf("sensitive header %q is forbidden", name)
		}
		if observedHeaderPattern.MatchString(name) {
			return fmt.Errorf("detector-derived header %q is forbidden", name)
		}
		if len(name) > 256 || len(h.Values) == 0 {
			return fmt.Errorf("invalid header %q", name)
		}
		for _, value := range h.Values {
			if err := validateHTTPHeaderValue(name, value); err != nil {
				return err
			}
			if err := validateSafeText("header "+name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateHTTPHeaderName(name string) error {
	return validateHTTPToken("header name", name)
}

func isHTTPTokenByte(b byte) bool {
	if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}

func validateHTTPHeaderValue(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("header %q value is not valid UTF-8", name)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("header %q value contains a control character", name)
		}
	}
	return nil
}

func validateHTTPToken(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s %q has surrounding whitespace", field, value)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s %q is not valid UTF-8", field, value)
	}
	for i := 0; i < len(value); i++ {
		if !isHTTPTokenByte(value[i]) {
			return fmt.Errorf("%s %q contains an invalid character", field, value)
		}
	}
	return nil
}

func validateHTTPProtocol(value string) error {
	if err := validateMetadataText("protocol", value); err != nil {
		return err
	}
	if !httpProtocolPattern.MatchString(value) {
		return fmt.Errorf("protocol %q is invalid", value)
	}
	return nil
}

func validateBody(body []byte, digest string, count int64) error {
	if len(body) > MaxHTTPSnapshotBodyBytes {
		return fmt.Errorf("body exceeds %d bytes", MaxHTTPSnapshotBodyBytes)
	}
	if count != int64(len(body)) {
		return fmt.Errorf("body_bytes=%d does not match body length %d", count, len(body))
	}
	if !isLowerHexSHA256(digest) {
		return errors.New("body_sha256 must be a 64-character lowercase SHA-256")
	}
	sum := sha256.Sum256(body)
	if digest != hex.EncodeToString(sum[:]) {
		return errors.New("body_sha256 does not match body")
	}
	if utf8.Valid(body) && len(body) > 0 {
		if err := validateBodySafeText("body", string(body)); err != nil {
			return err
		}
	}
	return nil
}

// Body payloads are bounded separately by MaxHTTPSnapshotBodyBytes. Reusing
// the metadata field limit here incorrectly rejected legitimate 1 MiB bodies.
func validateBodySafeText(field, value string) error {
	if emailPattern.MatchString(value) || secretPattern.MatchString(value) {
		return fmt.Errorf("%s contains sensitive data", field)
	}
	if strings.Contains(value, "@") {
		if u, err := url.Parse(value); err == nil && u.User != nil {
			return fmt.Errorf("%s contains URI userinfo", field)
		}
	}
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		if net.ParseIP(strings.Trim(u.Hostname(), "[]")) != nil {
			return fmt.Errorf("%s contains an unredacted IP address", field)
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
		return fmt.Errorf("%s contains an unredacted IP address", field)
	}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune("/?:,#[]() \t\r\n", r) }) {
		if net.ParseIP(part) != nil {
			return fmt.Errorf("%s contains an unredacted IP address", field)
		}
	}
	return nil
}

func validateSafeText(field, value string) error {
	if len(value) > maxHTTPSnapshotField {
		return fmt.Errorf("%s exceeds size limit", field)
	}
	if emailPattern.MatchString(value) || secretPattern.MatchString(value) {
		return fmt.Errorf("%s contains sensitive data", field)
	}
	if strings.Contains(value, "@") {
		if u, err := url.Parse(value); err == nil && u.User != nil {
			return fmt.Errorf("%s contains URI userinfo", field)
		}
	}
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		if net.ParseIP(strings.Trim(u.Hostname(), "[]")) != nil {
			return fmt.Errorf("%s contains an unredacted IP address", field)
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
		return fmt.Errorf("%s contains an unredacted IP address", field)
	}
	// Also catch IP literals embedded in URLs or prose.
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune("/?:,#[]() \t\r\n", r) }) {
		if net.ParseIP(part) != nil {
			return fmt.Errorf("%s contains an unredacted IP address", field)
		}
	}
	return nil
}

func validateMetadataText(field, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return validateSafeText(field, value)
}

// CanonicalSHA256 returns a deterministic SHA-256 over a normalized
// transaction. The stored Hash field is excluded, allowing callers to compute
// it before sealing a transaction.
func CanonicalSHA256(tx HTTPTransaction) (string, error) { return canonicalSHA256(tx) }

func canonicalSHA256(tx HTTPTransaction) (string, error) {
	type canonicalHeader struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	}
	normHeaders := func(in []HTTPHeader) []canonicalHeader {
		out := make([]canonicalHeader, 0, len(in))
		for _, h := range in {
			vals := append([]string(nil), h.Values...)
			sort.Strings(vals)
			out = append(out, canonicalHeader{Name: strings.ToLower(strings.TrimSpace(h.Name)), Values: vals})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Name == out[j].Name {
				return strings.Join(out[i].Values, "\x00") < strings.Join(out[j].Values, "\x00")
			}
			return out[i].Name < out[j].Name
		})
		return out
	}
	clone := struct {
		Version string `json:"version"`
		Request struct {
			Method     string            `json:"method"`
			Target     string            `json:"target"`
			Protocol   string            `json:"protocol"`
			Headers    []canonicalHeader `json:"headers,omitempty"`
			Body       []byte            `json:"body,omitempty"`
			BodySHA256 string            `json:"body_sha256"`
			BodyBytes  int64             `json:"body_bytes"`
		} `json:"request"`
		Response struct {
			StatusCode int               `json:"status_code"`
			Protocol   string            `json:"protocol"`
			Headers    []canonicalHeader `json:"headers,omitempty"`
			Body       []byte            `json:"body,omitempty"`
			BodySHA256 string            `json:"body_sha256"`
			BodyBytes  int64             `json:"body_bytes"`
		} `json:"response"`
		ExpectedOracleLabel OracleLabel `json:"expected_oracle_label"`
		Deployment          string      `json:"deployment"`
		Provenance          string      `json:"provenance"`
		Source              string      `json:"source"`
		Site                string      `json:"site"`
		Session             string      `json:"session"`
		Timestamp           time.Time   `json:"timestamp"`
		Seed                string      `json:"seed"`
		Run                 string      `json:"run"`
		Assertion           string      `json:"assertion"`
	}{
		Version: tx.Version, ExpectedOracleLabel: tx.ExpectedOracleLabel, Deployment: tx.Deployment, Provenance: tx.Provenance, Source: tx.Source, Site: tx.Site, Session: tx.Session, Timestamp: tx.Timestamp.UTC(), Seed: tx.Seed, Run: tx.Run, Assertion: tx.Assertion,
	}
	clone.Request.Method, clone.Request.Target, clone.Request.Protocol, clone.Request.Headers, clone.Request.Body, clone.Request.BodySHA256, clone.Request.BodyBytes = tx.Request.Method, tx.Request.Target, tx.Request.Protocol, normHeaders(tx.Request.Headers), tx.Request.Body, tx.Request.BodySHA256, tx.Request.BodyBytes
	clone.Response.StatusCode, clone.Response.Protocol, clone.Response.Headers, clone.Response.Body, clone.Response.BodySHA256, clone.Response.BodyBytes = tx.Response.StatusCode, tx.Response.Protocol, normHeaders(tx.Response.Headers), tx.Response.Body, tx.Response.BodySHA256, tx.Response.BodyBytes
	b, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ToCase projects the request and independent oracle into the existing Case
// type without changing that type or carrying response/WAF observations.
func (tx HTTPTransaction) ToCase() (Case, error) {
	if err := ValidateHTTPTransaction(tx); err != nil {
		return Case{}, err
	}
	header := make(map[string]string, len(tx.Request.Headers))
	for _, h := range tx.Request.Headers {
		header[h.Name] = strings.Join(h.Values, ", ")
	}
	return Case{Name: tx.Assertion, SourceFamily: tx.Source, Label: strings.ToLower(strings.TrimSpace(tx.ExpectedOracleLabel.Label)), Category: strings.ToLower(strings.TrimSpace(tx.ExpectedOracleLabel.Category)), Method: tx.Request.Method, Target: tx.Request.Target, Body: string(tx.Request.Body), Header: header}, nil
}
