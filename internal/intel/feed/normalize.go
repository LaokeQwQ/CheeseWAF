package feed

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	cvePattern  = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	avdPattern  = regexp.MustCompile(`(?i)\bAVD-[0-9]{4}-[0-9]{4,}\b`)
	ghsaPattern = regexp.MustCompile(`(?i)\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b`)
)

// Normalize canonicalizes an item: it cleans text, extracts CVE, AVD, and GHSA
// identifiers, normalizes references and product hints, and computes a stable
// content hash. It is idempotent for valid input.
//
// The content hash covers the canonical title, summary, link, publication
// time, identifiers, references, and product hints. It intentionally excludes
// ExternalID and SourceID so that the same advisory republished under a new
// feed identifier is still detected as a content replay.
func Normalize(item FeedItem) (FeedItem, error) {
	externalID, err := cleanText("external id", item.ExternalID, MaxExternalIDBytes)
	if err != nil {
		return FeedItem{}, err
	}
	title, err := cleanText("title", item.Title, MaxTitleBytes)
	if err != nil {
		return FeedItem{}, err
	}
	summary, err := cleanText("summary", item.Summary, MaxSummaryBytes)
	if err != nil {
		return FeedItem{}, err
	}

	item.ExternalID = externalID
	item.Title = title
	item.Summary = summary
	item.Link = normalizeLink(item.Link)
	if !item.Published.IsZero() {
		item.Published = item.Published.UTC()
	}

	if item.ExternalID == "" && item.Title == "" && item.Summary == "" &&
		item.Link == "" && item.Published.IsZero() && len(item.References) == 0 {
		return FeedItem{}, fmt.Errorf("%w: item has no identifier or content", ErrInvalidItem)
	}

	references := normalizeReferences(item.References, item.Link)
	products := normalizeProducts(item.Products)

	haystack := item.Title + "\n" + item.Summary + "\n" + item.Link
	for _, ref := range references {
		haystack += "\n" + ref
	}
	cves := extractIDs(cvePattern, haystack, item.CVEIDs)
	avds := extractIDs(avdPattern, haystack, item.AVDIDs)
	ghsas := extractIDs(ghsaPattern, haystack, item.GHSAIDs)

	item.References = references
	item.Products = products
	item.CVEIDs = cves
	item.AVDIDs = avds
	item.GHSAIDs = ghsas
	item.ContentHash = computeContentHash(item)
	if item.ExternalID == "" {
		item.ExternalID = "auto-" + item.ContentHash[:16]
	}
	return item, nil
}

// computeContentHash hashes length-prefixed canonical fields so no field
// boundary can collide with another. Lists must already be sorted and unique.
func computeContentHash(item FeedItem) string {
	h := sha256.New()
	writeHashField(h, item.Title)
	writeHashField(h, item.Summary)
	writeHashField(h, item.Link)
	writeHashField(h, item.Published.UTC().Format(time.RFC3339Nano))
	writeHashList(h, item.CVEIDs)
	writeHashList(h, item.AVDIDs)
	writeHashList(h, item.GHSAIDs)
	writeHashList(h, item.References)
	writeHashList(h, item.Products)
	return hex.EncodeToString(h.Sum(nil))
}

func writeHashField(h interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func writeHashList(h interface{ Write([]byte) (int, error) }, values []string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(values)))
	_, _ = h.Write(size[:])
	for _, value := range values {
		writeHashField(h, value)
	}
}

// cleanText collapses all whitespace to single spaces, drops control
// characters, and rejects invalid UTF-8 or values over the byte limit.
func cleanText(label, value string, limit int) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalid, label)
	}
	var b strings.Builder
	b.Grow(len(value))
	pendingSpace := false
	for _, r := range value {
		switch {
		case r == '\uFEFF':
			continue
		case unicode.IsSpace(r):
			if b.Len() > 0 {
				pendingSpace = true
			}
		case unicode.IsControl(r):
			continue
		default:
			if pendingSpace {
				b.WriteByte(' ')
				pendingSpace = false
			}
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > limit {
		return "", fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, limit)
	}
	return out, nil
}

// normalizeLink keeps only absolute http(s) links without credentials.
func normalizeLink(raw string) string {
	normalized, ok := normalizeAbsoluteURL(raw)
	if !ok {
		return ""
	}
	return normalized
}

func normalizeAbsoluteURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxLinkBytes {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), true
}

// normalizeReferences merges the primary link with the reference list, drops
// unsafe or duplicate URLs, sorts the result, and applies the bound.
func normalizeReferences(values []string, link string) []string {
	seen := make(map[string]struct{}, len(values)+1)
	out := make([]string, 0, len(values)+1)
	add := func(raw string) {
		if normalized, ok := normalizeAbsoluteURL(raw); ok {
			if _, exists := seen[normalized]; !exists {
				seen[normalized] = struct{}{}
				out = append(out, normalized)
			}
		}
	}
	add(link)
	for _, value := range values {
		add(value)
	}
	sort.Strings(out)
	if len(out) > MaxReferences {
		out = out[:MaxReferences]
	}
	return out
}

// normalizeProducts keeps bounded, non-empty product hints. Overlong or
// invalid hints are dropped rather than failing the whole feed.
func normalizeProducts(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value, err := cleanText("product hint", raw, MaxProductBytes)
		if err != nil || value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > MaxProducts {
		out = out[:MaxProducts]
	}
	return out
}

// extractIDs merges extracted and caller-provided identifiers, canonicalizes
// case, deduplicates, sorts, and applies the per-family bound.
func extractIDs(pattern *regexp.Regexp, haystack string, provided []string) []string {
	seen := make(map[string]struct{}, len(provided)+4)
	for _, match := range pattern.FindAllString(haystack, -1) {
		seen[strings.ToUpper(match)] = struct{}{}
	}
	for _, id := range provided {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" {
			seen[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > MaxIDs {
		out = out[:MaxIDs]
	}
	return out
}

// parseTime accepts the timestamp shapes found in RSS and Atom feeds. Invalid
// or missing timestamps yield the zero time so ingestion remains deterministic.
func parseTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		time.RFC1123Z,
		time.RFC1123,
		time.RFC822Z,
		time.RFC822,
		time.RFC850,
		time.ANSIC,
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
