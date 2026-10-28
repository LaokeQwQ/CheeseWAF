package feed

import (
	"errors"
	"strings"
	"testing"
)

func testSources() []Source {
	return []Source{
		{ID: "vendor", Name: "Vendor", URL: "https://vendor.example/feed.xml", Format: FormatRSS, Trust: TrustVendor, Enabled: true},
		{ID: "official", Name: "Official", URL: "https://official.example/feed.json", Format: FormatJSON, Trust: TrustOfficial, Enabled: true},
		{ID: "disabled", Name: "Disabled", URL: "https://disabled.example/feed.atom", Format: FormatAtom, Trust: TrustCommunity, Enabled: false},
	}
}

func TestRegistryResolve(t *testing.T) {
	registry, err := NewSourceRegistry(testSources())
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	source, err := registry.Resolve("vendor")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if source.URL != "https://vendor.example/feed.xml" || source.Trust != TrustVendor || source.Format != FormatRSS {
		t.Errorf("resolved source = %+v", source)
	}
	if !source.Enabled {
		t.Errorf("resolved source is disabled")
	}

	if _, err := registry.Resolve("missing"); !errors.Is(err, ErrUnknownSource) {
		t.Errorf("unknown id err = %v, want %v", err, ErrUnknownSource)
	}
	if _, err := registry.Resolve("disabled"); !errors.Is(err, ErrSourceDisabled) {
		t.Errorf("disabled err = %v, want %v", err, ErrSourceDisabled)
	}
	if source, ok := registry.Lookup("disabled"); !ok || source.Enabled {
		t.Errorf("Lookup disabled = %+v, %v", source, ok)
	}
	if _, ok := registry.Lookup("missing"); ok {
		t.Errorf("Lookup found unknown source")
	}

	sources := registry.Sources()
	if len(sources) != 3 {
		t.Fatalf("sources = %d, want 3", len(sources))
	}
	if sources[0].ID != "disabled" || sources[1].ID != "official" || sources[2].ID != "vendor" {
		t.Errorf("sources not sorted: %+v", sources)
	}
}

func TestRegistrySetEnabled(t *testing.T) {
	registry, err := NewSourceRegistry(testSources())
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	if err := registry.SetEnabled("disabled", true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, err := registry.Resolve("disabled"); err != nil {
		t.Fatalf("Resolve after enable: %v", err)
	}
	if err := registry.SetEnabled("vendor", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, err := registry.Resolve("vendor"); !errors.Is(err, ErrSourceDisabled) {
		t.Fatalf("Resolve after disable err = %v, want %v", err, ErrSourceDisabled)
	}
	if err := registry.SetEnabled("missing", true); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("SetEnabled unknown err = %v, want %v", err, ErrUnknownSource)
	}
}

func TestRegistryURLAllowlist(t *testing.T) {
	registry, err := NewSourceRegistry([]Source{
		{ID: "one", URL: "https://Example.com:443/feed", Trust: TrustVendor, Enabled: true},
		{ID: "two", URL: "https://example.com", Trust: TrustVendor, Enabled: true},
		{ID: "query", URL: "https://example.com/feed?tenant=acme", Trust: TrustVendor, Enabled: true},
		{ID: "disabled", URL: "https://disabled.example/feed.atom", Trust: TrustCommunity, Enabled: false},
	})
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	tests := []struct {
		name    string
		url     string
		wantID  string
		wantErr error
	}{
		{name: "case and default port", url: "https://EXAMPLE.com/feed", wantID: "one"},
		{name: "root path", url: "https://example.com/", wantID: "two"},
		{name: "query retained", url: "https://example.com/feed?tenant=acme", wantID: "query"},
		{name: "unknown url", url: "https://example.com/other", wantErr: ErrUnknownSource},
		{name: "ftp rejected", url: "ftp://example.com/feed", wantErr: ErrInvalidSource},
		{name: "relative rejected", url: "/feed", wantErr: ErrInvalidSource},
		{name: "credentials rejected", url: "https://user:pass@example.com/feed", wantErr: ErrInvalidSource},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := registry.ResolveURL(test.url)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("err = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveURL: %v", err)
			}
			if source.ID != test.wantID {
				t.Fatalf("id = %q, want %q", source.ID, test.wantID)
			}
		})
	}

	if _, err := registry.ResolveURL("https://disabled.example/feed.atom"); !errors.Is(err, ErrSourceDisabled) {
		t.Fatalf("disabled url err = %v, want %v", err, ErrSourceDisabled)
	}
}

func TestRegistryRejectsDuplicates(t *testing.T) {
	registry, err := NewSourceRegistry(testSources())
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	if err := registry.Register(Source{ID: "vendor", URL: "https://other.example/feed", Trust: TrustVendor, Enabled: true}); !errors.Is(err, ErrDuplicateSource) {
		t.Errorf("duplicate id err = %v, want %v", err, ErrDuplicateSource)
	}
	if err := registry.Register(Source{ID: "new", URL: "https://VENDOR.example:443/feed.xml", Trust: TrustVendor, Enabled: true}); !errors.Is(err, ErrDuplicateSource) {
		t.Errorf("duplicate url err = %v, want %v", err, ErrDuplicateSource)
	}
	registry2, err := NewSourceRegistry([]Source{
		{ID: "a", URL: "https://example.com/feed", Trust: TrustVendor, Enabled: true},
		{ID: "b", URL: "https://EXAMPLE.com/feed", Trust: TrustVendor, Enabled: true},
	})
	if !errors.Is(err, ErrDuplicateSource) || registry2 != nil {
		t.Errorf("duplicate normalized url err = %v, registry = %v", err, registry2)
	}
}

func TestRegistryRejectsInvalidSources(t *testing.T) {
	tests := []struct {
		name   string
		source Source
	}{
		{name: "empty id", source: Source{ID: "", URL: "https://example.com/feed", Trust: TrustVendor, Enabled: true}},
		{name: "bad id", source: Source{ID: "bad id", URL: "https://example.com/feed", Trust: TrustVendor, Enabled: true}},
		{name: "missing url", source: Source{ID: "s", Trust: TrustVendor, Enabled: true}},
		{name: "relative url", source: Source{ID: "s", URL: "/feed", Trust: TrustVendor, Enabled: true}},
		{name: "ftp url", source: Source{ID: "s", URL: "ftp://example.com/feed", Trust: TrustVendor, Enabled: true}},
		{name: "credentials", source: Source{ID: "s", URL: "https://user:pass@example.com/feed", Trust: TrustVendor, Enabled: true}},
		{name: "bad trust", source: Source{ID: "s", URL: "https://example.com/feed", Trust: "trusted", Enabled: true}},
		{name: "bad format", source: Source{ID: "s", URL: "https://example.com/feed", Format: "csv", Trust: TrustVendor, Enabled: true}},
		{name: "overlong name", source: Source{ID: "s", Name: strings.Repeat("n", maxSourceNameBytes+1), URL: "https://example.com/feed", Trust: TrustVendor, Enabled: true}},
		{name: "overlong url", source: Source{ID: "s", URL: "https://example.com/" + strings.Repeat("a", MaxLinkBytes), Trust: TrustVendor, Enabled: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSourceRegistry([]Source{test.source}); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("err = %v, want %v", err, ErrInvalidSource)
			}
		})
	}
}

func TestRegistryDefaultsAndParse(t *testing.T) {
	registry, err := NewSourceRegistry([]Source{
		{ID: "vendor", URL: "https://vendor.example/feed.xml", Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	source, err := registry.Resolve("vendor")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if source.Trust != TrustUnknown || source.Format != "" {
		t.Errorf("defaults = trust %q format %q", source.Trust, source.Format)
	}

	items, err := registry.Parse("vendor", []byte(rssFixture))
	if err != nil {
		t.Fatalf("registry Parse: %v", err)
	}
	if len(items) != 3 || items[0].SourceID != "vendor" {
		t.Fatalf("items = %+v", items)
	}

	if _, err := registry.Parse("missing", []byte(rssFixture)); !errors.Is(err, ErrUnknownSource) {
		t.Errorf("unknown parse err = %v, want %v", err, ErrUnknownSource)
	}
	if err := registry.SetEnabled("vendor", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, err := registry.Parse("vendor", []byte(rssFixture)); !errors.Is(err, ErrSourceDisabled) {
		t.Errorf("disabled parse err = %v, want %v", err, ErrSourceDisabled)
	}
}

func TestRegistryDeclaredFormatMismatch(t *testing.T) {
	registry, err := NewSourceRegistry([]Source{
		{ID: "rss", URL: "https://example.com/feed", Format: FormatRSS, Trust: TrustVendor, Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	if _, err := registry.Parse("rss", []byte(jsonFixture)); !errors.Is(err, ErrFormatMismatch) {
		t.Fatalf("err = %v, want %v", err, ErrFormatMismatch)
	}
}

func TestSourceRegistryZeroValue(t *testing.T) {
	var registry SourceRegistry
	source := Source{ID: "vendor", URL: "https://vendor.example/feed.xml", Trust: TrustVendor, Enabled: true}
	if err := registry.Register(source); err != nil {
		t.Fatalf("zero-value Register: %v", err)
	}
	if _, err := registry.Resolve("vendor"); err != nil {
		t.Fatalf("zero-value Resolve: %v", err)
	}
}

func TestRegistryEmpty(t *testing.T) {
	registry, err := NewSourceRegistry(nil)
	if err != nil {
		t.Fatalf("NewSourceRegistry: %v", err)
	}
	if len(registry.Sources()) != 0 {
		t.Fatalf("empty registry has sources")
	}
	if _, err := registry.Resolve("anything"); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("err = %v, want %v", err, ErrUnknownSource)
	}
}
