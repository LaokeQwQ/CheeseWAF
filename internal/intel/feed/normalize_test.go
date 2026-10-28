package feed

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNormalizeStable(t *testing.T) {
	first := FeedItem{
		ExternalID: "adv-1",
		SourceID:   "vendor",
		Title:      "CVE-2024-1234   in\nWidget",
		Summary:    "  Text\twith  spaces ",
		Link:       "HTTPS://Vendor.Example/Advisory/1",
		Published:  time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC),
		Products:   []string{" widget ", "b", "widget"},
		References: []string{
			"https://Example.com/ref",
			"https://example.com/ref",
			"javascript:alert(1)",
			"/relative",
		},
	}
	firstNormalized, err := Normalize(first)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	second := first
	second.ExternalID = "adv-2"
	second.SourceID = "other"
	second.Title = "CVE-2024-1234 in Widget"
	second.Summary = "Text with spaces"
	second.Link = "https://vendor.example/Advisory/1"
	second.Published = time.Date(2024, 1, 2, 17, 4, 5, 0, time.FixedZone("CEST", 2*60*60))
	second.Products = []string{"widget", "b"}
	second.References = []string{"https://example.com/ref"}
	secondNormalized, err := Normalize(second)
	if err != nil {
		t.Fatalf("Normalize variant: %v", err)
	}

	if firstNormalized.ContentHash != secondNormalized.ContentHash {
		t.Errorf("hash changed across stable variants: %s vs %s", firstNormalized.ContentHash, secondNormalized.ContentHash)
	}
	if len(firstNormalized.ContentHash) != 64 {
		t.Fatalf("hash length = %d", len(firstNormalized.ContentHash))
	}
	if _, err := hex.DecodeString(firstNormalized.ContentHash); err != nil {
		t.Fatalf("hash is not hex: %v", err)
	}
	if _, offset := secondNormalized.Published.Zone(); offset != 0 {
		t.Errorf("published not normalized to UTC: %s", secondNormalized.Published)
	}
	if firstNormalized.Title != "CVE-2024-1234 in Widget" {
		t.Errorf("title = %q", firstNormalized.Title)
	}
	if firstNormalized.Summary != "Text with spaces" {
		t.Errorf("summary = %q", firstNormalized.Summary)
	}
	if firstNormalized.Link != "https://vendor.example/Advisory/1" {
		t.Errorf("link = %q", firstNormalized.Link)
	}
	if got, want := strings.Join(firstNormalized.Products, ","), "b,widget"; got != want {
		t.Errorf("products = %q, want %q", got, want)
	}
	if got, want := strings.Join(firstNormalized.References, ","), "https://example.com/ref,https://vendor.example/Advisory/1"; got != want {
		t.Errorf("references = %q, want %q", got, want)
	}

	again, err := Normalize(firstNormalized)
	if err != nil {
		t.Fatalf("Normalize twice: %v", err)
	}
	if again.ContentHash != firstNormalized.ContentHash || again.ExternalID != firstNormalized.ExternalID {
		t.Errorf("normalization is not idempotent: %+v vs %+v", again, firstNormalized)
	}
}

func TestNormalizeExtractsIdentifiersAndProducts(t *testing.T) {
	item := FeedItem{
		ExternalID: "adv-9",
		Title:      "CVE-2024-0001 and cve-2024-0002",
		Summary:    "AVD-2023-1111 / GHSA-abcd-efgh-ijkl",
		Link:       "https://vendor.example/advisory/CVE-2024-0003",
		References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
		CVEIDs:     []string{"cve-2024-0004", "CVE-2024-0001"},
		Products:   []string{"Widget", " widget ", "Gateway"},
	}
	normalized, err := Normalize(item)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got, want := strings.Join(normalized.CVEIDs, ","), "CVE-2024-0001,CVE-2024-0002,CVE-2024-0003,CVE-2024-0004"; got != want {
		t.Errorf("cves = %q, want %q", got, want)
	}
	if got, want := strings.Join(normalized.AVDIDs, ","), "AVD-2023-1111"; got != want {
		t.Errorf("avds = %q, want %q", got, want)
	}
	if got, want := strings.Join(normalized.GHSAIDs, ","), "GHSA-ABCD-EFGH-IJKL"; got != want {
		t.Errorf("ghsas = %q, want %q", got, want)
	}
	if got, want := strings.Join(normalized.Products, ","), "Gateway,Widget,widget"; got != want {
		t.Errorf("products = %q, want %q", got, want)
	}
}

func TestNormalizeAutoIDAndHashExcludesExternalID(t *testing.T) {
	first := FeedItem{Title: "Advisory", Summary: "body", Published: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	normalized, err := Normalize(first)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !strings.HasPrefix(normalized.ExternalID, "auto-") {
		t.Errorf("auto id = %q", normalized.ExternalID)
	}
	if normalized.ExternalID != "auto-"+normalized.ContentHash[:16] {
		t.Errorf("auto id does not derive from hash: %q", normalized.ExternalID)
	}

	second := first
	second.ExternalID = "different-id"
	other, err := Normalize(second)
	if err != nil {
		t.Fatalf("Normalize second: %v", err)
	}
	if normalized.ContentHash != other.ContentHash {
		t.Errorf("hash depends on external id: %s vs %s", normalized.ContentHash, other.ContentHash)
	}
}

func TestNormalizeRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		item    FeedItem
		wantErr error
	}{
		{name: "empty", item: FeedItem{}, wantErr: ErrInvalidItem},
		{name: "invalid utf8 title", item: FeedItem{Title: string([]byte{0xff, 0xfe})}, wantErr: ErrInvalid},
		{name: "overlong title", item: FeedItem{Title: strings.Repeat("a", MaxTitleBytes+1)}, wantErr: ErrInvalid},
		{name: "overlong summary", item: FeedItem{Summary: strings.Repeat("a", MaxSummaryBytes+1)}, wantErr: ErrInvalid},
		{name: "overlong external id", item: FeedItem{ExternalID: strings.Repeat("a", MaxExternalIDBytes+1)}, wantErr: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Normalize(test.item)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("err = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestNormalizeBoundsCollections(t *testing.T) {
	manyIDs := make([]string, MaxIDs+10)
	for i := range manyIDs {
		manyIDs[i] = fmt.Sprintf("CVE-2024-%04d", i+1000)
	}
	manyProducts := make([]string, MaxProducts+5)
	for i := range manyProducts {
		manyProducts[i] = fmt.Sprintf("product-%02d", i)
	}
	item := FeedItem{
		ExternalID: "bounded",
		Title:      "bounded",
		CVEIDs:     manyIDs,
		Products:   manyProducts,
		References: make([]string, MaxReferences+5),
	}
	for i := range item.References {
		item.References[i] = fmt.Sprintf("https://example.com/%02d", i)
	}
	normalized, err := Normalize(item)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(normalized.CVEIDs) != MaxIDs {
		t.Errorf("cve count = %d, want %d", len(normalized.CVEIDs), MaxIDs)
	}
	if len(normalized.Products) != MaxProducts {
		t.Errorf("product count = %d, want %d", len(normalized.Products), MaxProducts)
	}
	if len(normalized.References) != MaxReferences {
		t.Errorf("reference count = %d, want %d", len(normalized.References), MaxReferences)
	}
}

func TestNormalizeDropsUnsafeReferencesAndOverlongProducts(t *testing.T) {
	item := FeedItem{
		ExternalID: "adv",
		Title:      "advisory",
		Link:       "https://user:pass@example.com/advisory",
		References: []string{
			"javascript:alert(1)",
			"data:text/html,<script>",
			"https://ok.example/ref",
			"https://ok.example/ref",
		},
		Products: []string{strings.Repeat("p", MaxProductBytes+1), "safe"},
	}
	normalized, err := Normalize(item)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if normalized.Link != "" {
		t.Errorf("credential link retained: %q", normalized.Link)
	}
	if got, want := strings.Join(normalized.References, ","), "https://ok.example/ref"; got != want {
		t.Errorf("references = %q, want %q", got, want)
	}
	if got, want := strings.Join(normalized.Products, ","), "safe"; got != want {
		t.Errorf("products = %q, want %q", got, want)
	}
}

func TestNormalizeZeroTimeIsStable(t *testing.T) {
	first, err := Normalize(FeedItem{ExternalID: "a", Title: "same"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	second, err := Normalize(FeedItem{ExternalID: "a", Title: "same", Published: time.Time{}})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if first.ContentHash != second.ContentHash {
		t.Errorf("zero time changed hash: %s vs %s", first.ContentHash, second.ContentHash)
	}
}
