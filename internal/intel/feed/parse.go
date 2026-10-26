package feed

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// DetectFormat sniffs the feed encoding from the body. XML declarations and
// namespaces are skipped; only the root element decides RSS versus Atom.
func DetectFormat(body []byte) (Format, error) {
	if err := checkBody(body); err != nil {
		return "", err
	}
	data := bytes.TrimSpace(bytes.TrimPrefix(body, utf8BOM))
	if len(data) == 0 {
		return "", ErrEmptyBody
	}
	switch data[0] {
	case '{':
		return FormatJSON, nil
	case '<':
		decoder := xml.NewDecoder(bytes.NewReader(data))
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				return "", fmt.Errorf("%w: no root element", ErrUnsupportedFormat)
			}
			if err != nil {
				return "", fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			if start, ok := token.(xml.StartElement); ok {
				switch start.Name.Local {
				case "rss":
					return FormatRSS, nil
				case "feed":
					return FormatAtom, nil
				default:
					return "", fmt.Errorf("%w: root element %q", ErrUnsupportedFormat, start.Name.Local)
				}
			}
		}
	default:
		return "", fmt.Errorf("%w: unrecognized body", ErrUnsupportedFormat)
	}
}

// Parse detects the feed format and returns normalized items with SourceID set
// to source.ID. source.URL is used as the base for relative links. A declared
// source.Format must match the body; parsing never performs network I/O.
func Parse(source Source, body []byte) ([]FeedItem, error) {
	if source.Format != "" && !source.Format.Valid() {
		return nil, fmt.Errorf("%w: format %q", ErrInvalidSource, source.Format)
	}
	format, err := DetectFormat(body)
	if err != nil {
		return nil, err
	}
	if source.Format != "" && source.Format != format {
		return nil, fmt.Errorf("%w: declared %s, body is %s", ErrFormatMismatch, source.Format, format)
	}

	body = bytes.TrimPrefix(body, utf8BOM)
	base := parseBaseURL(source.URL)
	var items []FeedItem
	switch format {
	case FormatRSS:
		items, err = parseRSS(body, base)
	case FormatAtom:
		items, err = parseAtom(body, base)
	case FormatJSON:
		items, err = parseJSONFeed(body, base)
	default:
		err = fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
	if err != nil {
		return nil, err
	}
	return finalize(items, source.ID)
}

// ParseRSS parses an RSS 2.0 document. Relative links cannot be resolved
// without a source URL and are dropped.
func ParseRSS(body []byte) ([]FeedItem, error) {
	if err := checkBody(body); err != nil {
		return nil, err
	}
	items, err := parseRSS(bytes.TrimPrefix(body, utf8BOM), nil)
	if err != nil {
		return nil, err
	}
	return finalize(items, "")
}

// ParseAtom parses an Atom 1.0 document. Relative links are resolved against
// the feed's self link when present.
func ParseAtom(body []byte) ([]FeedItem, error) {
	if err := checkBody(body); err != nil {
		return nil, err
	}
	items, err := parseAtom(bytes.TrimPrefix(body, utf8BOM), nil)
	if err != nil {
		return nil, err
	}
	return finalize(items, "")
}

// ParseJSONFeed parses a JSON Feed 1.0 or 1.1 document. Relative links are
// dropped because a standalone body has no base URL.
func ParseJSONFeed(body []byte) ([]FeedItem, error) {
	if err := checkBody(body); err != nil {
		return nil, err
	}
	items, err := parseJSONFeed(bytes.TrimPrefix(body, utf8BOM), nil)
	if err != nil {
		return nil, err
	}
	return finalize(items, "")
}

func checkBody(body []byte) error {
	if len(body) == 0 {
		return ErrEmptyBody
	}
	if len(body) > MaxBodyBytes {
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrBodyTooLarge, len(body), MaxBodyBytes)
	}
	return nil
}

func finalize(items []FeedItem, sourceID string) ([]FeedItem, error) {
	if len(items) > MaxItems {
		return nil, fmt.Errorf("%w: %d exceeds %d", ErrTooManyItems, len(items), MaxItems)
	}
	out := make([]FeedItem, 0, len(items))
	for index := range items {
		normalized, err := Normalize(items[index])
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		normalized.SourceID = sourceID
		out = append(out, normalized)
	}
	return out, nil
}

func parseBaseURL(raw string) *url.URL {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil
	}
	return parsed
}

// resolveLink resolves a possibly relative link and rejects non-http(s)
// schemes, credentials, and malformed URLs.
func resolveLink(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if !parsed.IsAbs() {
		if base == nil {
			return ""
		}
		parsed = base.ResolveReference(parsed)
	}
	normalized, ok := normalizeAbsoluteURL(parsed.String())
	if !ok {
		return ""
	}
	return normalized
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

type rssDocument struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string    `xml:"title"`
	Link        string    `xml:"link"`
	GUID        rssGUID   `xml:"guid"`
	Description string    `xml:"description"`
	Encoded     string    `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
	PubDate     string    `xml:"pubDate"`
	DCDate      string    `xml:"http://purl.org/dc/elements/1.1/ date"`
	Categories  []string  `xml:"category"`
	Source      rssSource `xml:"source"`
}

type rssGUID struct {
	Value       string `xml:",chardata"`
	IsPermaLink string `xml:"isPermaLink,attr"`
}

type rssSource struct {
	URL   string `xml:"url,attr"`
	Value string `xml:",chardata"`
}

func parseRSS(body []byte, base *url.URL) ([]FeedItem, error) {
	var document rssDocument
	if err := xml.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("%w: rss: %v", ErrInvalid, err)
	}
	items := make([]FeedItem, 0, len(document.Channel.Items))
	for _, entry := range document.Channel.Items {
		link := resolveLink(base, entry.Link)
		guid := strings.TrimSpace(entry.GUID.Value)
		// RSS defaults isPermaLink to true, but opaque GUIDs are common. Only
		// treat a GUID as a link when the attribute says so explicitly or the
		// value is visibly absolute.
		permaLink := strings.TrimSpace(entry.GUID.IsPermaLink)
		if link == "" && guid != "" {
			switch {
			case strings.EqualFold(permaLink, "true"):
				link = resolveLink(base, guid)
			case permaLink == "" && strings.Contains(guid, "://"):
				link = resolveLink(base, guid)
			}
		}
		externalID := guid
		if externalID == "" {
			externalID = link
		}
		references := make([]string, 0, 1)
		if entry.Source.URL != "" {
			references = append(references, entry.Source.URL)
		}
		items = append(items, FeedItem{
			ExternalID: externalID,
			Title:      entry.Title,
			Summary:    firstNonEmpty(entry.Description, entry.Encoded),
			Link:       link,
			Published:  parseTime(firstNonEmpty(entry.PubDate, entry.DCDate)),
			References: references,
			Products:   append([]string(nil), entry.Categories...),
		})
	}
	return items, nil
}

type atomDocument struct {
	XMLName xml.Name    `xml:"feed"`
	Links   []atomLink  `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	ID         string         `xml:"id"`
	Title      string         `xml:"title"`
	Summary    string         `xml:"summary"`
	Content    string         `xml:"content"`
	Published  string         `xml:"published"`
	Updated    string         `xml:"updated"`
	Links      []atomLink     `xml:"link"`
	Categories []atomCategory `xml:"category"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

type atomCategory struct {
	Term  string `xml:"term,attr"`
	Label string `xml:"label,attr"`
}

func parseAtom(body []byte, base *url.URL) ([]FeedItem, error) {
	var document atomDocument
	if err := xml.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("%w: atom: %v", ErrInvalid, err)
	}
	if base == nil {
		for _, link := range document.Links {
			if strings.EqualFold(strings.TrimSpace(link.Rel), "self") {
				base = parseBaseURL(link.Href)
				if base != nil {
					break
				}
			}
		}
	}
	items := make([]FeedItem, 0, len(document.Entries))
	for _, entry := range document.Entries {
		var link string
		references := make([]string, 0, len(entry.Links))
		for _, candidate := range entry.Links {
			resolved := resolveLink(base, candidate.Href)
			if resolved == "" {
				continue
			}
			references = append(references, resolved)
			rel := strings.ToLower(strings.TrimSpace(candidate.Rel))
			if link == "" && (rel == "" || rel == "alternate") {
				link = resolved
			}
		}
		if link == "" && len(references) > 0 {
			link = references[0]
		}
		products := make([]string, 0, len(entry.Categories))
		for _, category := range entry.Categories {
			products = append(products, firstNonEmpty(category.Term, category.Label))
		}
		externalID := strings.TrimSpace(entry.ID)
		if externalID == "" {
			externalID = link
		}
		items = append(items, FeedItem{
			ExternalID: externalID,
			Title:      entry.Title,
			Summary:    firstNonEmpty(entry.Summary, entry.Content),
			Link:       link,
			Published:  parseTime(firstNonEmpty(entry.Published, entry.Updated)),
			References: references,
			Products:   products,
		})
	}
	return items, nil
}

type jsonDocument struct {
	Version string     `json:"version"`
	Items   []jsonItem `json:"items"`
}

type jsonItem struct {
	ID            flexString `json:"id"`
	URL           string     `json:"url"`
	ExternalURL   string     `json:"external_url"`
	Title         string     `json:"title"`
	Summary       string     `json:"summary"`
	ContentText   string     `json:"content_text"`
	ContentHTML   string     `json:"content_html"`
	DatePublished string     `json:"date_published"`
	DateModified  string     `json:"date_modified"`
	Tags          []string   `json:"tags"`
}

// flexString accepts JSON Feed identifiers encoded as strings or numbers.
type flexString string

func (s *flexString) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	switch {
	case trimmed == "null":
		*s = ""
		return nil
	case len(trimmed) > 0 && trimmed[0] == '"':
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*s = flexString(value)
		return nil
	case len(trimmed) > 0 && (trimmed[0] == '-' || (trimmed[0] >= '0' && trimmed[0] <= '9')):
		*s = flexString(trimmed)
		return nil
	default:
		return fmt.Errorf("feed: json feed id must be a string or number")
	}
}

func parseJSONFeed(body []byte, base *url.URL) ([]FeedItem, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var document jsonDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: json feed: %v", ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: json feed has trailing content", ErrInvalid)
	}
	switch strings.TrimSpace(document.Version) {
	case "https://jsonfeed.org/version/1", "https://jsonfeed.org/version/1.0", "https://jsonfeed.org/version/1.1":
	default:
		return nil, fmt.Errorf("%w: json feed version %q", ErrUnsupportedFormat, document.Version)
	}
	items := make([]FeedItem, 0, len(document.Items))
	for _, entry := range document.Items {
		link := resolveLink(base, firstNonEmpty(entry.URL, entry.ExternalURL))
		references := make([]string, 0, 2)
		for _, raw := range []string{entry.URL, entry.ExternalURL} {
			if resolved := resolveLink(base, raw); resolved != "" {
				references = append(references, resolved)
			}
		}
		externalID := strings.TrimSpace(string(entry.ID))
		if externalID == "" {
			externalID = link
		}
		items = append(items, FeedItem{
			ExternalID: externalID,
			Title:      entry.Title,
			Summary:    firstNonEmpty(entry.Summary, entry.ContentText, entry.ContentHTML),
			Link:       link,
			Published:  parseTime(firstNonEmpty(entry.DatePublished, entry.DateModified)),
			References: references,
			Products:   append([]string(nil), entry.Tags...),
		})
	}
	return items, nil
}
