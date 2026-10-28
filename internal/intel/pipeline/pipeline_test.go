package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
)

var testClock = time.Date(2025, 10, 1, 12, 0, 0, 0, time.UTC)

func rssBody(guid, title, summary string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>Advisories</title>
<link>https://feeds.example.com/</link>
<description>test</description>
<item>
<title>` + title + `</title>
<link>https://advisories.example.com/` + guid + `</link>
<guid isPermaLink="false">` + guid + `</guid>
<description>` + summary + `</description>
<pubDate>Wed, 01 Oct 2025 10:00:00 GMT</pubDate>
<category>widget</category>
</item>
</channel></rss>`)
}

func nestedExtraction() intel.Extraction {
	return intel.Extraction{
		Confidence: 0.9,
		CVEIDs:     []string{"CVE-2025-1234"},
		Products:   []string{"widget"},
		Request: intel.RequestShape{
			Method:         "POST",
			Path:           "/api/upload",
			NestedArrays:   true,
			ParameterNames: []string{"data"},
		},
		References: []string{"https://advisories.example.com/adv-1"},
	}
}

func testRegistry(t *testing.T, configs ...SourceConfig) *Registry {
	t.Helper()
	registry, err := NewRegistry(configs)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return registry
}

func sourceConfig(id, trust string) SourceConfig {
	return SourceConfig{
		ID:      id,
		Name:    id,
		URL:     "https://feeds.example.com/" + id + ".xml",
		Format:  "rss",
		Trust:   trust,
		Enabled: true,
	}
}

func testPipeline(t *testing.T, registry *Registry, extractor Extractor, now *time.Time, ttl time.Duration) *Pipeline {
	t.Helper()
	p, err := New(Config{
		Registry:  registry,
		Extractor: extractor,
		TTL:       ttl,
		Now: func() time.Time {
			return *now
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestIngestOfficialFeedProducesDraftCandidate(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, 2*time.Hour)

	candidates, err := p.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "CVE-2025-1234 widget RCE", "Nested array crash in widget"), 1, intel.Scope{SiteID: "site-1"})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	candidate := candidates[0]
	if candidate.State != intel.CandidateDraft {
		t.Errorf("state = %q, want %q", candidate.State, intel.CandidateDraft)
	}
	if candidate.Action != intel.ActionLog {
		t.Errorf("action = %q, want %q", candidate.Action, intel.ActionLog)
	}
	if candidate.TTL != 2*time.Hour {
		t.Errorf("TTL = %s, want 2h", candidate.TTL)
	}
	if expires := candidate.ExpiresAt(); !expires.Equal(testClock.Add(2 * time.Hour)) {
		t.Errorf("expires = %s", expires)
	}
	if candidate.SiteID != "site-1" {
		t.Errorf("site = %q", candidate.SiteID)
	}
	if candidate.Provenance.SourceID != "vendor-feed" || candidate.Provenance.SourceTrust != intel.TrustVendor {
		t.Errorf("provenance = %+v", candidate.Provenance)
	}
	if candidate.Impact.CandidateID != candidate.ID {
		t.Errorf("impact candidate id = %q, want %q", candidate.Impact.CandidateID, candidate.ID)
	}
	if candidate.Impact.Verdict != impact.VerdictNeedsReview {
		t.Errorf("impact verdict = %q, want review without profiles", candidate.Impact.Verdict)
	}
	compiled, err := intel.DecodeCompiledRule([]byte(candidate.RuleJSON))
	if err != nil {
		t.Fatalf("DecodeCompiledRule: %v", err)
	}
	if compiled.Rule.Enabled {
		t.Error("rule must start disabled")
	}
	if compiled.Rule.Action != intel.ActionLog {
		t.Errorf("rule action = %q", compiled.Rule.Action)
	}
	if compiled.Scope.IsGlobal() || compiled.Scope.SiteID != "site-1" {
		t.Errorf("scope = %+v", compiled.Scope)
	}
	if compiled.Scope.PathPrefix != "/api/upload" {
		t.Errorf("path prefix = %q", compiled.Scope.PathPrefix)
	}
	if candidate.Provenance.ItemID == "" || candidate.ItemID != candidate.Provenance.ItemID {
		t.Errorf("item provenance mismatch: candidate=%q provenance=%q", candidate.ItemID, candidate.Provenance.ItemID)
	}
}

func TestIngestCommunitySingleQuarantined(t *testing.T) {
	registry := testRegistry(t, sourceConfig("community-feed", "community"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)

	candidates, err := p.Ingest(context.Background(), "community-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 1, intel.Scope{SiteID: "site-1"})
	if !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v, want ErrQuarantined", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates = %d, want 0", len(candidates))
	}
}

func TestIngestCommunityCorroboratedBySecondSource(t *testing.T) {
	registry := testRegistry(t,
		sourceConfig("community-a", "community"),
		sourceConfig("community-b", "community"),
	)
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)
	body := rssBody("adv-1", "CVE-2025-1234", "shared summary")

	if candidates, err := p.Ingest(context.Background(), "community-a", body, 1, intel.Scope{SiteID: "site-1"}); !errors.Is(err, ErrQuarantined) || len(candidates) != 0 {
		t.Fatalf("first source: candidates=%d err=%v, want quarantine", len(candidates), err)
	}
	candidates, err := p.Ingest(context.Background(), "community-b", body, 1, intel.Scope{SiteID: "site-1"})
	if err != nil {
		t.Fatalf("second source: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	if candidates[0].Decision.IndependentSources != 2 {
		t.Errorf("independent sources = %d, want 2", candidates[0].Decision.IndependentSources)
	}
	if candidates[0].Decision.Trust != intel.TrustCommunity {
		t.Errorf("trust = %q", candidates[0].Decision.Trust)
	}
}

func TestIngestDuplicateAndReplayRejected(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)
	ctx := context.Background()

	if _, err := p.Ingest(ctx, "vendor-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 5, intel.Scope{SiteID: "site-1"}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if candidates, err := p.Ingest(ctx, "vendor-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 5, intel.Scope{SiteID: "site-1"}); !errors.Is(err, ErrDuplicate) || len(candidates) != 0 {
		t.Fatalf("duplicate: candidates=%d err=%v, want ErrDuplicate", len(candidates), err)
	}
	if candidates, err := p.Ingest(ctx, "vendor-feed", rssBody("adv-2", "CVE-2025-9999", "other"), 4, intel.Scope{SiteID: "site-1"}); !errors.Is(err, ErrDuplicate) || !errors.Is(err, feed.ErrReplay) || len(candidates) != 0 {
		t.Fatalf("replay: candidates=%d err=%v, want replay error", len(candidates), err)
	}
}

func TestIngestVagueAdvisoryYieldsNoSafeRule(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(intel.Extraction{Confidence: 0.4}), &now, time.Hour)

	candidates, err := p.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "security update", "vague advisory"), 1, intel.Scope{SiteID: "site-1"})
	if !errors.Is(err, ErrNoSafeRule) {
		t.Fatalf("err = %v, want ErrNoSafeRule", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates = %d, want 0", len(candidates))
	}
}

func TestIngestCapsCandidatesPerItem(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	extractor := ExtractorFunc(func(context.Context, intel.Item) ([]intel.Extraction, error) {
		return []intel.Extraction{
			nestedExtraction(),
			func() intel.Extraction {
				e := nestedExtraction()
				e.Request.ParameterNames = []string{"payload"}
				return e
			}(),
			func() intel.Extraction {
				e := nestedExtraction()
				e.Request.ParameterNames = []string{"form"}
				return e
			}(),
		}, nil
	})
	p := testPipeline(t, registry, extractor, &now, time.Hour)

	candidates, err := p.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "CVE-2025-1234", "summary"), 1, intel.Scope{SiteID: "site-1"})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
	if len(candidates) != DefaultMaxCandidatesPerItem {
		t.Fatalf("candidates = %d, want %d", len(candidates), DefaultMaxCandidatesPerItem)
	}
}

func TestIngestRejectsGlobalScope(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)

	if _, err := p.Ingest(context.Background(), "vendor-feed", rssBody("adv-1", "title", "summary"), 1, intel.Scope{SiteID: "*"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	extractor := FixedExtractor(nestedExtraction())

	if _, err := New(Config{Registry: registry, Extractor: extractor, TTL: -time.Second}); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative TTL err = %v", err)
	}
	if _, err := New(Config{Registry: registry, Extractor: extractor, TTL: intel.MaxCandidateTTL + time.Second}); !errors.Is(err, ErrInvalid) {
		t.Errorf("large TTL err = %v", err)
	}
	if _, err := New(Config{Registry: registry, Extractor: extractor, MaxCandidatesPerItem: HardMaxCandidatesPerItem + 1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("candidate cap err = %v", err)
	}
	if _, err := New(Config{Registry: registry}); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing extractor err = %v", err)
	}
}

func TestIngestItemBuildsCandidateFromPreparedItem(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)
	item := intel.Item{
		ID:          "item-html-1",
		SourceID:    "vendor-feed",
		Title:       "CVE-2025-1234 advisory",
		ContentHash: strings.Repeat("a", 64),
		RawExcerpt:  "nested arrays in widget",
	}

	candidates, err := p.IngestItem(context.Background(), item, []intel.Extraction{nestedExtraction()}, intel.Scope{SiteID: "site-1"})
	if err != nil {
		t.Fatalf("IngestItem: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	candidate := candidates[0]
	if candidate.ItemID != item.ID {
		t.Errorf("item id = %q, want %q", candidate.ItemID, item.ID)
	}
	if candidate.State != intel.CandidateDraft || candidate.Action != intel.ActionLog {
		t.Errorf("state/action = %q/%q", candidate.State, candidate.Action)
	}
	compiled, err := intel.DecodeCompiledRule([]byte(candidate.RuleJSON))
	if err != nil {
		t.Fatalf("DecodeCompiledRule: %v", err)
	}
	if compiled.Rule.Enabled || compiled.Scope.IsGlobal() {
		t.Errorf("rule enabled=%v scope=%+v", compiled.Rule.Enabled, compiled.Scope)
	}
	if candidate.Impact.CandidateID != candidate.ID {
		t.Errorf("impact candidate id = %q", candidate.Impact.CandidateID)
	}
}

func TestIngestItemQuarantinesCommunityItem(t *testing.T) {
	registry := testRegistry(t, sourceConfig("community-feed", "community"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)
	item := intel.Item{ID: "item-html-1", SourceID: "community-feed", ContentHash: strings.Repeat("b", 64)}

	candidates, err := p.IngestItem(context.Background(), item, []intel.Extraction{nestedExtraction()}, intel.Scope{SiteID: "site-1"})
	if !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v, want ErrQuarantined", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates = %d, want 0", len(candidates))
	}
}

func TestIngestItemRequiresExtractionAndValidInput(t *testing.T) {
	registry := testRegistry(t, sourceConfig("vendor-feed", "vendor"))
	now := testClock
	p := testPipeline(t, registry, FixedExtractor(nestedExtraction()), &now, time.Hour)

	if _, err := p.IngestItem(context.Background(), intel.Item{SourceID: "vendor-feed"}, []intel.Extraction{nestedExtraction()}, intel.Scope{SiteID: "site-1"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing item id err = %v", err)
	}
	item := intel.Item{ID: "item-html-1", SourceID: "vendor-feed"}
	if _, err := p.IngestItem(context.Background(), item, nil, intel.Scope{SiteID: "site-1"}); !errors.Is(err, ErrNoSafeRule) {
		t.Errorf("no extraction err = %v", err)
	}
	if _, err := p.IngestItem(context.Background(), item, []intel.Extraction{nestedExtraction()}, intel.Scope{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("global scope err = %v", err)
	}
}

func TestRegistryMapsFeedSourceTrust(t *testing.T) {
	registry := testRegistry(t,
		sourceConfig("official-feed", "official"),
		sourceConfig("vendor-feed", "vendor"),
		sourceConfig("community-feed", "community"),
		sourceConfig("unknown-feed", ""),
	)
	want := map[string]intel.TrustLevel{
		"official-feed":  intel.TrustOfficial,
		"vendor-feed":    intel.TrustVendor,
		"community-feed": intel.TrustCommunity,
		"unknown-feed":   intel.TrustUnknown,
	}
	sources := registry.IntelSources()
	if len(sources) != len(want) {
		t.Fatalf("sources = %d, want %d", len(sources), len(want))
	}
	for _, source := range sources {
		if got := want[source.ID]; source.Trust != got {
			t.Errorf("source %q trust = %q, want %q", source.ID, source.Trust, got)
		}
		if source.Type != "rss" {
			t.Errorf("source %q type = %q", source.ID, source.Type)
		}
	}

	if _, err := NewRegistry([]SourceConfig{sourceConfig("typo-feed", "trusted")}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid trust err = %v", err)
	}

	disabled := testRegistry(t, SourceConfig{
		ID:      "disabled-feed",
		URL:     "https://feeds.example.com/disabled.xml",
		Trust:   "official",
		Enabled: false,
	})
	if _, err := disabled.Resolve("disabled-feed"); !errors.Is(err, feed.ErrSourceDisabled) {
		t.Errorf("disabled resolve err = %v", err)
	}
	if _, err := registry.Resolve("missing"); !errors.Is(err, feed.ErrUnknownSource) {
		t.Errorf("missing resolve err = %v", err)
	}
	if !strings.Contains(registry.IntelSources()[0].URL, "feeds.example.com") {
		t.Errorf("url = %q", registry.IntelSources()[0].URL)
	}
}
