// Package intel turns untrusted vulnerability intelligence into reviewable WAF
// rule candidates. Fetching, HTML normalization, extraction validation, and
// rule compilation are deterministic; nothing here activates a candidate or
// mutates active rules.
package intel

import (
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// TrustLevel describes how much confidence the operator has in a source.
type TrustLevel string

const (
	TrustOfficial  TrustLevel = "official"
	TrustVendor    TrustLevel = "vendor"
	TrustCommunity TrustLevel = "community"
	TrustUnknown   TrustLevel = "unknown"
)

// Valid reports whether the trust level is one of the supported values.
func (t TrustLevel) Valid() bool {
	switch t {
	case TrustOfficial, TrustVendor, TrustCommunity, TrustUnknown:
		return true
	default:
		return false
	}
}

// Rank returns a monotonic ordering for trust levels. Unknown is the lowest.
func (t TrustLevel) Rank() int {
	switch t {
	case TrustOfficial:
		return 4
	case TrustVendor:
		return 3
	case TrustCommunity:
		return 2
	default:
		return 1
	}
}

// ParseTrustLevel normalizes an operator-provided trust value. Anything that is
// not recognized is treated as unknown rather than silently trusted.
func ParseTrustLevel(raw string) TrustLevel {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(TrustOfficial):
		return TrustOfficial
	case string(TrustVendor):
		return TrustVendor
	case string(TrustCommunity):
		return TrustCommunity
	default:
		return TrustUnknown
	}
}

// Source is a registered vulnerability intelligence feed.
type Source struct {
	ID           string     `json:"id" yaml:"id"`
	Type         string     `json:"type" yaml:"type"`
	URL          string     `json:"url" yaml:"url"`
	Trust        TrustLevel `json:"trust" yaml:"trust"`
	Enabled      bool       `json:"enabled" yaml:"enabled"`
	ETag         string     `json:"etag,omitempty" yaml:"etag,omitempty"`
	LastModified string     `json:"last_modified,omitempty" yaml:"last_modified,omitempty"`
}

// Item is a normalized intelligence item after fetching and HTML extraction.
type Item struct {
	ID                     string    `json:"id"`
	SourceID               string    `json:"source_id"`
	ExternalIDs            []string  `json:"external_ids,omitempty"`
	Title                  string    `json:"title,omitempty"`
	ContentHash            string    `json:"content_hash,omitempty"`
	PublishedAt            time.Time `json:"published_at,omitempty"`
	Products               []string  `json:"products,omitempty"`
	AffectedVersions       []string  `json:"affected_versions,omitempty"`
	AttackVector           string    `json:"attack_vector,omitempty"`
	ExploitStatus          string    `json:"exploit_status,omitempty"`
	References             []string  `json:"references,omitempty"`
	RawExcerpt             string    `json:"raw_excerpt,omitempty"`
	CorroboratingSourceIDs []string  `json:"corroborating_source_ids,omitempty"`
}

// RequestShape is the request-side signal extracted from an advisory.
type RequestShape struct {
	Method           string   `json:"method,omitempty"`
	Path             string   `json:"path,omitempty"`
	ContentType      string   `json:"content_type,omitempty"`
	ParameterNames   []string `json:"parameter_names,omitempty"`
	Markers          []string `json:"markers,omitempty"`
	NestedArrays     bool     `json:"nested_arrays,omitempty"`
	SessionParameter string   `json:"session_parameter,omitempty"`
	UploadProgress   bool     `json:"upload_progress,omitempty"`
}

// ResponseEvidence is the response-side signal extracted from an advisory.
type ResponseEvidence struct {
	StatusCodes            []int    `json:"status_codes,omitempty"`
	HeaderNames            []string `json:"header_names,omitempty"`
	BodyMarkers            []string `json:"body_markers,omitempty"`
	OversizedSessionCookie bool     `json:"oversized_session_cookie,omitempty"`
}

// Extraction is the structured, JSON-compatible output of an Extractor. It
// contains no executable content; only the deterministic RuleCompiler may turn
// it into a rule.
type Extraction struct {
	CVEIDs           []string         `json:"cve_ids,omitempty"`
	Products         []string         `json:"products,omitempty"`
	AffectedVersions []string         `json:"affected_versions,omitempty"`
	Request          RequestShape     `json:"request,omitempty"`
	Response         ResponseEvidence `json:"response,omitempty"`
	Confidence       float64          `json:"confidence"`
	References       []string         `json:"references,omitempty"`
}

// CandidateState is the review-first rollout state of a candidate.
type CandidateState string

const (
	CandidateDraft    CandidateState = "draft"
	CandidateShadow   CandidateState = "shadow"
	CandidateCanary   CandidateState = "canary"
	CandidateActive   CandidateState = "active"
	CandidateExpired  CandidateState = "expired"
	CandidateRejected CandidateState = "rejected"
)

// Valid reports whether the state is one of the supported values.
func (s CandidateState) Valid() bool {
	switch s {
	case CandidateDraft, CandidateShadow, CandidateCanary, CandidateActive, CandidateExpired, CandidateRejected:
		return true
	default:
		return false
	}
}

// Candidate actions mirror the custom rule action set.
const (
	ActionLog       = "log"
	ActionChallenge = "challenge"
	ActionBlock     = "block"
)

// Scope bounds where a generated rule may run. A candidate is never global.
type Scope struct {
	SiteID     string   `json:"site_id"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	Methods    []string `json:"methods,omitempty"`
}

// IsGlobal reports whether the scope would apply outside a single site.
func (s Scope) IsGlobal() bool {
	site := strings.ToLower(strings.TrimSpace(s.SiteID))
	return site == "" || site == "*" || site == "global" || site == "all"
}

// CompiledRule is the exact rule payload stored in Candidate.RuleJSON.
type CompiledRule struct {
	Rule  config.CustomRuleConfig `json:"rule"`
	Scope Scope                   `json:"scope"`
}

// Provenance records how a candidate was produced.
type Provenance struct {
	SourceID    string     `json:"source_id"`
	SourceTrust TrustLevel `json:"source_trust"`
	ItemID      string     `json:"item_id"`
	Extractor   string     `json:"extractor"`
	References  []string   `json:"references,omitempty"`
	Approved    bool       `json:"approved,omitempty"`
	ApprovedBy  string     `json:"approved_by,omitempty"`
}

// Candidate is a compiled rule awaiting review and rollout.
type Candidate struct {
	ID         string         `json:"id"`
	ItemID     string         `json:"item_id"`
	SiteID     string         `json:"site_id"`
	RuleJSON   string         `json:"rule_json"`
	Action     string         `json:"action"`
	State      CandidateState `json:"state"`
	Confidence float64        `json:"confidence"`
	Provenance Provenance     `json:"provenance"`
	TTL        time.Duration  `json:"ttl"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// ExpiresAt returns the candidate expiry, or the zero time when TTL is unset.
func (c Candidate) ExpiresAt() time.Time {
	if c.TTL <= 0 {
		return time.Time{}
	}
	return c.CreatedAt.Add(c.TTL)
}
