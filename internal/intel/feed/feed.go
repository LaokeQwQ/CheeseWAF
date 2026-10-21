// Package feed parses vulnerability intelligence feeds (RSS 2.0, Atom 1.0,
// and JSON Feed 1.x) into normalized items and provides source allowlisting
// and replay protection. It performs no network I/O: fetching and SSRF checks
// belong to the caller.
package feed

import (
	"errors"
	"strings"
	"time"
)

const (
	// MaxBodyBytes is the maximum accepted feed body size.
	MaxBodyBytes = 1 << 20
	// MaxItems is the maximum number of items accepted from one feed body.
	MaxItems = 500

	// MaxTitleBytes bounds a normalized item title.
	MaxTitleBytes = 512
	// MaxSummaryBytes bounds a normalized item summary.
	MaxSummaryBytes = 64 << 10
	// MaxExternalIDBytes bounds a feed-provided item identifier.
	MaxExternalIDBytes = 256
	// MaxLinkBytes bounds a normalized primary or reference URL.
	MaxLinkBytes = 2048
	// MaxReferences bounds the number of references retained per item.
	MaxReferences = 32
	// MaxIDs bounds each extracted identifier family per item.
	MaxIDs = 64
	// MaxProducts bounds the number of product hints retained per item.
	MaxProducts = 32
	// MaxProductBytes bounds one product hint.
	MaxProductBytes = 128
)

// Errors returned by parsing, normalization, deduplication, and source
// registry operations. Callers can use errors.Is to distinguish policy
// rejection from malformed input.
var (
	ErrInvalid           = errors.New("feed: invalid input")
	ErrEmptyBody         = errors.New("feed: empty body")
	ErrBodyTooLarge      = errors.New("feed: body exceeds size limit")
	ErrTooManyItems      = errors.New("feed: too many items")
	ErrUnsupportedFormat = errors.New("feed: unsupported feed format")
	ErrFormatMismatch    = errors.New("feed: declared format does not match body")
	ErrInvalidItem       = errors.New("feed: invalid item")
	ErrInvalidSource     = errors.New("feed: invalid source")
	ErrUnknownSource     = errors.New("feed: unknown source")
	ErrSourceDisabled    = errors.New("feed: source disabled")
	ErrDuplicateSource   = errors.New("feed: duplicate source")
	ErrDuplicate         = errors.New("feed: duplicate item")
	ErrReplay            = errors.New("feed: replayed item sequence")
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

// Format identifies a supported feed encoding.
type Format string

const (
	FormatRSS  Format = "rss"
	FormatAtom Format = "atom"
	FormatJSON Format = "json"
)

// Valid reports whether the format is supported.
func (f Format) Valid() bool {
	switch f {
	case FormatRSS, FormatAtom, FormatJSON:
		return true
	default:
		return false
	}
}

// ParseFormat normalizes an operator-provided format value. Unrecognized
// values yield an empty format so callers can auto-detect.
func ParseFormat(raw string) Format {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "rss", "rss2", "rss2.0":
		return FormatRSS
	case "atom", "atom1", "atom1.0":
		return FormatAtom
	case "json", "jsonfeed", "json_feed":
		return FormatJSON
	default:
		return ""
	}
}

// Source is an allowlisted intelligence feed. URL is compared after
// normalization against the URL that a fetcher was instructed to retrieve.
type Source struct {
	ID      string     `json:"id" yaml:"id"`
	Name    string     `json:"name,omitempty" yaml:"name,omitempty"`
	URL     string     `json:"url" yaml:"url"`
	Format  Format     `json:"format,omitempty" yaml:"format,omitempty"`
	Trust   TrustLevel `json:"trust" yaml:"trust"`
	Enabled bool       `json:"enabled" yaml:"enabled"`
}

// FeedItem is one normalized entry from a feed. SourceID and ContentHash are
// filled by Parse; Normalize fills IDs, references, product hints, and the
// stable content hash.
type FeedItem struct {
	ExternalID  string    `json:"external_id"`
	SourceID    string    `json:"source_id,omitempty"`
	Title       string    `json:"title,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Link        string    `json:"link,omitempty"`
	Published   time.Time `json:"published,omitempty"`
	CVEIDs      []string  `json:"cve_ids,omitempty"`
	AVDIDs      []string  `json:"avd_ids,omitempty"`
	GHSAIDs     []string  `json:"ghsa_ids,omitempty"`
	References  []string  `json:"references,omitempty"`
	Products    []string  `json:"products,omitempty"`
	ContentHash string    `json:"content_hash,omitempty"`
}
