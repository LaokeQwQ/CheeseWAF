package feed

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func dedupeItem(id, summary string) FeedItem {
	return FeedItem{
		ExternalID: id,
		Title:      "CVE-2024-1234 advisory",
		Summary:    summary,
		Link:       "https://vendor.example/advisory/" + id,
		Published:  time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestDedupeRejectsDuplicateID(t *testing.T) {
	deduper := NewDedupe()
	item := dedupeItem("adv-1", "first")

	if err := deduper.Accept("vendor", 1, item); err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if err := deduper.Accept("vendor", 2, item); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Accept err = %v, want %v", err, ErrDuplicate)
	}

	changed := item
	changed.Summary = "updated body"
	if err := deduper.Accept("vendor", 3, changed); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("changed content with same id err = %v, want %v", err, ErrDuplicate)
	}

	otherSource := NewDedupe()
	if err := otherSource.Accept("community", 1, item); err != nil {
		t.Fatalf("same item from another source should be independent: %v", err)
	}
}

func TestDedupeRejectsContentHashReplay(t *testing.T) {
	deduper := NewDedupe()
	item := dedupeItem("adv-1", "identical content")
	if err := deduper.Accept("vendor", 5, item); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	replay := item
	replay.ExternalID = "adv-1-republished"
	if err := deduper.Accept("vendor", 6, replay); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("content replay err = %v, want %v", err, ErrDuplicate)
	}

	normalizedFirst, err := Normalize(item)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	normalizedReplay, err := Normalize(replay)
	if err != nil {
		t.Fatalf("Normalize replay: %v", err)
	}
	if normalizedFirst.ContentHash != normalizedReplay.ContentHash {
		t.Fatalf("fixture hashes differ: %s vs %s", normalizedFirst.ContentHash, normalizedReplay.ContentHash)
	}
}

func TestDedupeRejectsReplayedSequence(t *testing.T) {
	deduper := NewDedupe()
	if err := deduper.Accept("vendor", 10, dedupeItem("adv-1", "one")); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	replay := dedupeItem("adv-2", "two")
	if err := deduper.Accept("vendor", 9, replay); !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want %v", err, ErrReplay)
	}
	if err := deduper.Accept("vendor", 10, replay); err != nil {
		t.Fatalf("equal sequence for the same fetch should be allowed: %v", err)
	}
	if err := deduper.Accept("vendor", 12, dedupeItem("adv-3", "three")); err != nil {
		t.Fatalf("advancing sequence: %v", err)
	}
}

func TestDedupeValidatesInput(t *testing.T) {
	tests := []struct {
		name     string
		sourceID string
		item     FeedItem
		wantErr  error
	}{
		{name: "empty source", sourceID: "", item: dedupeItem("adv-1", "x"), wantErr: ErrInvalid},
		{
			name:     "source mismatch",
			sourceID: "vendor",
			item:     FeedItem{ExternalID: "adv-1", SourceID: "other", Title: "x"},
			wantErr:  ErrInvalid,
		},
		{
			name:     "bad hash length",
			sourceID: "vendor",
			item:     FeedItem{ExternalID: "adv-1", Title: "x", ContentHash: "abc"},
			wantErr:  ErrInvalid,
		},
		{
			name:     "bad hash encoding",
			sourceID: "vendor",
			item:     FeedItem{ExternalID: "adv-1", Title: "x", ContentHash: strings.Repeat("z", 64)},
			wantErr:  ErrInvalid,
		},
		{
			name:     "hash mismatch",
			sourceID: "vendor",
			item:     FeedItem{ExternalID: "adv-1", Title: "x", ContentHash: strings.Repeat("0", 64)},
			wantErr:  ErrInvalid,
		},
		{
			name:     "invalid item",
			sourceID: "vendor",
			item:     FeedItem{},
			wantErr:  ErrInvalidItem,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := NewDedupe().Accept(test.sourceID, 1, test.item)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("err = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestDedupeFilter(t *testing.T) {
	deduper := NewDedupe()
	items := []FeedItem{
		dedupeItem("adv-1", "one"),
		dedupeItem("adv-1", "one"),
		dedupeItem("adv-2", "two"),
	}
	accepted, rejected := deduper.Filter("vendor", 1, items)
	if len(accepted) != 2 {
		t.Fatalf("accepted = %d, want 2", len(accepted))
	}
	if len(rejected) != 1 {
		t.Fatalf("rejected = %d, want 1", len(rejected))
	}
	if !errors.Is(rejected[0].Err, ErrDuplicate) {
		t.Fatalf("rejection err = %v, want %v", rejected[0].Err, ErrDuplicate)
	}
	for _, item := range accepted {
		if item.ContentHash == "" || item.SourceID != "vendor" {
			t.Errorf("accepted item not normalized: %+v", item)
		}
	}
}

func TestDedupeReset(t *testing.T) {
	deduper := NewDedupe()
	item := dedupeItem("adv-1", "one")
	if err := deduper.Accept("vendor", 5, item); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	deduper.Reset("vendor")
	if err := deduper.Accept("vendor", 1, item); err != nil {
		t.Fatalf("after reset sequence should be forgotten: %v", err)
	}
}

func TestDedupeZeroValue(t *testing.T) {
	var dedupe Dedupe
	if err := dedupe.Accept("vendor", 1, dedupeItem("adv-1", "one")); err != nil {
		t.Fatalf("zero-value Accept: %v", err)
	}
	if err := dedupe.Accept("vendor", 1, dedupeItem("adv-1", "one")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("zero-value duplicate err = %v, want %v", err, ErrDuplicate)
	}
}

func TestDedupeParsedFeed(t *testing.T) {
	body := `{
	  "version": "https://jsonfeed.org/version/1.1",
	  "items": [
	    {"id": "same", "url": "https://example.com/a", "title": "advisory", "date_published": "2024-01-01T00:00:00Z"},
	    {"id": "same", "url": "https://example.com/a", "title": "advisory", "date_published": "2024-01-01T00:00:00Z"},
	    {"id": "other", "url": "https://example.com/b", "title": "advisory", "date_published": "2024-01-01T00:00:00Z"}
	  ]
	}`
	items, err := Parse(Source{ID: "json", URL: "https://json.example/feed.json"}, []byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	accepted, rejected := NewDedupe().Filter("json", 1, items)
	if len(accepted) != 2 || len(rejected) != 1 {
		t.Fatalf("accepted=%d rejected=%d, want 2/1", len(accepted), len(rejected))
	}
	if !errors.Is(rejected[0].Err, ErrDuplicate) {
		t.Fatalf("err = %v, want %v", rejected[0].Err, ErrDuplicate)
	}
}

func TestDedupeBoundsRetainedEntries(t *testing.T) {
	d := NewDedupe()
	for i := 0; i < maxDedupeEntries+100; i++ {
		item := FeedItem{ExternalID: fmt.Sprintf("id-%d", i), Title: fmt.Sprintf("item %d", i), Link: fmt.Sprintf("https://example.test/%d", i)}
		if err := d.Accept("source", uint64(i+1), item); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}
	state := d.sources["source"]
	if state == nil {
		t.Fatal("source state missing")
	}
	if len(state.ids) > maxDedupeEntries || len(state.hashes) > maxDedupeEntries || len(state.order) > maxDedupeEntries {
		t.Fatalf("retained state grew past bound: ids=%d hashes=%d order=%d", len(state.ids), len(state.hashes), len(state.order))
	}
}
