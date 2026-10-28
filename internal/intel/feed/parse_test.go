package feed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const rssFixture = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>Vendor advisories</title>
    <link>https://vendor.example/feed.xml</link>
    <item>
      <title><![CDATA[CVE-2024-12345 in Acme Widget]]></title>
      <link>/advisories/1</link>
      <guid isPermaLink="false">adv-1</guid>
      <description><![CDATA[Exploit details for CVE-2024-12345 and GHSA-abcd-efgh-ijkl.]]></description>
      <pubDate>Mon, 02 Jan 2024 15:04:05 GMT</pubDate>
      <category>acme-widget</category>
      <category>acme-widget</category>
      <source url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345">NVD</source>
    </item>
    <item>
      <title>No publish date, dc date instead</title>
      <link>https://vendor.example/advisories/2</link>
      <guid>adv-2</guid>
      <description>Plain item.</description>
      <dc:date>2024-02-03T04:05:06Z</dc:date>
      <category>other</category>
    </item>
    <item>
      <title>AVD item</title>
      <guid>adv-3</guid>
      <description>AVD-2023-9999 affects thing.</description>
    </item>
  </channel>
</rss>`

const atomFixture = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom advisories</title>
  <link rel="self" href="https://atom.example/feeds/security.atom"/>
  <entry>
    <id>tag:atom.example,2024:1</id>
    <title type="html">GHSA-1234-5678-9abc &amp; more</title>
    <summary type="html"><![CDATA[<p>CVE-2024-0001 affects <b>Widget</b></p>]]></summary>
    <published>2024-03-04T05:06:07Z</published>
    <updated>2024-03-05T00:00:00Z</updated>
    <link rel="alternate" href="/posts/1"/>
    <link rel="enclosure" href="https://cdn.example/patch.diff"/>
    <category term="Widget"/>
    <category term="widget"/>
  </entry>
  <entry>
    <id>tag:atom.example,2024:2</id>
    <title>Updated only</title>
    <summary>No published value</summary>
    <updated>2024-04-01T00:00:00+02:00</updated>
    <link href="https://other.example/x"/>
  </entry>
</feed>`

const jsonFixture = `{
  "version": "https://jsonfeed.org/version/1.1",
  "title": "JSON advisories",
  "items": [
    {
      "id": 12345,
      "url": "/advisories/1",
      "title": "CVE-2024-7777 in Gateway",
      "summary": "AVD-2022-4444 also referenced",
      "content_text": "ignored because summary wins",
      "date_published": "2024-05-06T07:08:09Z",
      "tags": ["gateway", "Gateway"]
    },
    {
      "id": "j-2",
      "external_url": "https://json.example/a/2",
      "title": "No date item",
      "content_html": "<p>GHSA-aaaa-bbbb-cccc</p>"
    },
    {
      "id": "j-3",
      "url": "/relative",
      "title": "Relative link item",
      "summary": "text"
    }
  ]
}`

func TestParseRSS(t *testing.T) {
	source := Source{ID: "vendor", URL: "https://vendor.example/feed.xml", Format: FormatRSS, Trust: TrustVendor, Enabled: true}
	items, err := Parse(source, []byte(rssFixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}

	first := items[0]
	if first.SourceID != "vendor" || first.ExternalID != "adv-1" {
		t.Errorf("identity = %q/%q", first.SourceID, first.ExternalID)
	}
	if first.Title != "CVE-2024-12345 in Acme Widget" {
		t.Errorf("title = %q", first.Title)
	}
	if first.Link != "https://vendor.example/advisories/1" {
		t.Errorf("relative link = %q", first.Link)
	}
	if !first.Published.Equal(time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)) {
		t.Errorf("published = %s", first.Published)
	}
	if got, want := strings.Join(first.CVEIDs, ","), "CVE-2024-12345"; got != want {
		t.Errorf("cve ids = %q, want %q", got, want)
	}
	if got, want := strings.Join(first.GHSAIDs, ","), "GHSA-ABCD-EFGH-IJKL"; got != want {
		t.Errorf("ghsa ids = %q, want %q", got, want)
	}
	if got, want := strings.Join(first.Products, ","), "acme-widget"; got != want {
		t.Errorf("products = %q, want %q", got, want)
	}
	if !contains(first.References, "https://nvd.nist.gov/vuln/detail/CVE-2024-12345") {
		t.Errorf("references = %v, missing NVD source", first.References)
	}

	second := items[1]
	if !second.Published.Equal(time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("dc:date published = %s", second.Published)
	}
	if second.ExternalID != "adv-2" {
		t.Errorf("external id = %q", second.ExternalID)
	}

	third := items[2]
	if !third.Published.IsZero() {
		t.Errorf("missing date = %s, want zero", third.Published)
	}
	if third.Link != "" {
		t.Errorf("missing link = %q, want empty", third.Link)
	}
	if got, want := strings.Join(third.AVDIDs, ","), "AVD-2023-9999"; got != want {
		t.Errorf("avd ids = %q, want %q", got, want)
	}
}

func TestParseAtom(t *testing.T) {
	items, err := ParseAtom([]byte(atomFixture))
	if err != nil {
		t.Fatalf("ParseAtom: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	first := items[0]
	if first.ExternalID != "tag:atom.example,2024:1" {
		t.Errorf("external id = %q", first.ExternalID)
	}
	if first.Link != "https://atom.example/posts/1" {
		t.Errorf("relative link = %q", first.Link)
	}
	if !contains(first.References, "https://cdn.example/patch.diff") {
		t.Errorf("references = %v, missing enclosure", first.References)
	}
	if !first.Published.Equal(time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)) {
		t.Errorf("published = %s", first.Published)
	}
	if got, want := strings.Join(first.GHSAIDs, ","), "GHSA-1234-5678-9ABC"; got != want {
		t.Errorf("ghsa ids = %q, want %q", got, want)
	}
	if got, want := strings.Join(first.CVEIDs, ","), "CVE-2024-0001"; got != want {
		t.Errorf("cve ids = %q, want %q", got, want)
	}
	if !strings.Contains(first.Summary, "<b>Widget</b>") {
		t.Errorf("CDATA summary = %q", first.Summary)
	}
	if len(first.Products) != 2 {
		t.Errorf("products = %v, want both category variants", first.Products)
	}

	second := items[1]
	if !second.Published.Equal(time.Date(2024, 3, 31, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("updated fallback published = %s", second.Published)
	}
	if second.Link != "https://other.example/x" {
		t.Errorf("absolute link = %q", second.Link)
	}
	if second.Summary != "No published value" {
		t.Errorf("summary = %q", second.Summary)
	}
}

func TestParseAtomRejectsWrongRoot(t *testing.T) {
	if _, err := ParseAtom([]byte(`<rss><channel></channel></rss>`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want %v", err, ErrInvalid)
	}
	if _, err := ParseRSS([]byte(atomFixture)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rss parser err = %v, want %v", err, ErrInvalid)
	}
}

func TestParseJSONFeed(t *testing.T) {
	source := Source{ID: "json", URL: "https://json.example/feeds/feed.json", Format: FormatJSON, Trust: TrustCommunity, Enabled: true}
	items, err := Parse(source, []byte(jsonFixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	first := items[0]
	if first.ExternalID != "12345" {
		t.Errorf("numeric id = %q, want 12345", first.ExternalID)
	}
	if first.Link != "https://json.example/advisories/1" {
		t.Errorf("relative link = %q", first.Link)
	}
	if !first.Published.Equal(time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Errorf("published = %s", first.Published)
	}
	if got, want := strings.Join(first.CVEIDs, ","), "CVE-2024-7777"; got != want {
		t.Errorf("cve ids = %q, want %q", got, want)
	}
	if got, want := strings.Join(first.AVDIDs, ","), "AVD-2022-4444"; got != want {
		t.Errorf("avd ids = %q, want %q", got, want)
	}
	if first.Summary != "AVD-2022-4444 also referenced" {
		t.Errorf("summary = %q", first.Summary)
	}

	second := items[1]
	if second.ExternalID != "j-2" || second.Link != "https://json.example/a/2" {
		t.Errorf("second identity = %q/%q", second.ExternalID, second.Link)
	}
	if !second.Published.IsZero() {
		t.Errorf("missing JSON date = %s", second.Published)
	}
	if got, want := strings.Join(second.GHSAIDs, ","), "GHSA-AAAA-BBBB-CCCC"; got != want {
		t.Errorf("ghsa ids = %q, want %q", got, want)
	}

	third := items[2]
	if third.Link != "https://json.example/relative" {
		t.Errorf("relative url = %q", third.Link)
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    Format
		wantErr error
	}{
		{name: "rss", body: rssFixture, want: FormatRSS},
		{name: "atom", body: atomFixture, want: FormatAtom},
		{name: "json", body: jsonFixture, want: FormatJSON},
		{name: "bom json", body: "\uFEFF" + jsonFixture, want: FormatJSON},
		{name: "empty", body: "", wantErr: ErrEmptyBody},
		{name: "whitespace", body: " \n\t", wantErr: ErrEmptyBody},
		{name: "garbage", body: "not a feed", wantErr: ErrUnsupportedFormat},
		{name: "rdf", body: `<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`, wantErr: ErrUnsupportedFormat},
		{name: "broken xml", body: `<rss`, wantErr: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DetectFormat([]byte(test.body))
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("err = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DetectFormat: %v", err)
			}
			if got != test.want {
				t.Fatalf("format = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseRejectsMalformedAndOversized(t *testing.T) {
	tests := []struct {
		name    string
		source  Source
		body    []byte
		wantErr error
	}{
		{
			name:    "empty body",
			source:  Source{ID: "s", URL: "https://example.com/feed"},
			body:    nil,
			wantErr: ErrEmptyBody,
		},
		{
			name:    "oversized body",
			source:  Source{ID: "s", URL: "https://example.com/feed"},
			body:    bytes.Repeat([]byte("a"), MaxBodyBytes+1),
			wantErr: ErrBodyTooLarge,
		},
		{
			name:    "malformed rss",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatRSS},
			body:    []byte(`<rss><channel><item><title>x</title>`),
			wantErr: ErrInvalid,
		},
		{
			name:    "malformed atom",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatAtom},
			body:    []byte(`<feed xmlns="http://www.w3.org/2005/Atom"><entry>`),
			wantErr: ErrInvalid,
		},
		{
			name:    "malformed json",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatJSON},
			body:    []byte(`{"version":"https://jsonfeed.org/version/1.1","items":[`),
			wantErr: ErrInvalid,
		},
		{
			name:    "json trailing content",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatJSON},
			body:    []byte(`{"version":"https://jsonfeed.org/version/1.1","items":[]}{}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "unsupported json version",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatJSON},
			body:    []byte(`{"version":"https://jsonfeed.org/version/2","items":[]}`),
			wantErr: ErrUnsupportedFormat,
		},
		{
			name:    "declared format mismatch",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatAtom},
			body:    []byte(rssFixture),
			wantErr: ErrFormatMismatch,
		},
		{
			name:    "invalid declared format",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: "csv"},
			body:    []byte(rssFixture),
			wantErr: ErrInvalidSource,
		},
		{
			name:    "rss body too malformed for parser",
			source:  Source{ID: "s", URL: "https://example.com/feed", Format: FormatRSS},
			body:    []byte(`<rss><channel><item><title>unterminated`),
			wantErr: ErrInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.source, test.body)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("err = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestParseItemLimit(t *testing.T) {
	items := make([]map[string]any, MaxItems+1)
	for i := range items {
		items[i] = map[string]any{"id": fmt.Sprintf("item-%d", i), "title": "advisory"}
	}
	body, err := json.Marshal(map[string]any{
		"version": "https://jsonfeed.org/version/1.1",
		"items":   items,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(body) > MaxBodyBytes {
		t.Fatalf("fixture unexpectedly exceeds body limit: %d", len(body))
	}
	_, err = Parse(Source{ID: "s", URL: "https://example.com/feed"}, body)
	if !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("err = %v, want %v", err, ErrTooManyItems)
	}

	body, err = json.Marshal(map[string]any{
		"version": "https://jsonfeed.org/version/1.1",
		"items":   items[:MaxItems],
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := Parse(Source{ID: "s", URL: "https://example.com/feed"}, body)
	if err != nil {
		t.Fatalf("Parse at limit: %v", err)
	}
	if len(parsed) != MaxItems {
		t.Fatalf("items = %d, want %d", len(parsed), MaxItems)
	}
}

func TestParseUnsafeAndRelativeLinks(t *testing.T) {
	body := `<rss><channel>
	  <item>
	    <title>Unsafe</title>
	    <guid>unsafe-1</guid>
	    <link>javascript:alert(1)</link>
	    <description>javascript:alert(2)</description>
	  </item>
	  <item>
	    <title>Relative without base</title>
	    <guid>rel-1</guid>
	    <link>/advisories/1</link>
	  </item>
	</channel></rss>`
	items, err := Parse(Source{ID: "s", URL: ""}, []byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if items[0].Link != "" || len(items[0].References) != 0 {
		t.Errorf("unsafe link retained: link=%q refs=%v", items[0].Link, items[0].References)
	}
	if items[0].ExternalID != "unsafe-1" {
		t.Errorf("unsafe item external id = %q", items[0].ExternalID)
	}
	if items[1].Link != "" {
		t.Errorf("relative link without base = %q, want empty", items[1].Link)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
