package storage

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestSiteConfigRoundTripPreservesNoSQLSemanticSwitch(t *testing.T) {
	original := config.SiteConfig{
		ID:        "site-a",
		Name:      "site-a",
		Enabled:   true,
		Domains:   []string{"example.test"},
		Upstreams: []config.UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
		WAF: config.WAFConfig{
			Enabled: true,
			Mode:    "block",
			SemanticEngines: config.SemanticEngineSwitches{
				NoSQL: true,
				SSTI:  true,
			},
		},
	}
	site := SiteFromConfig(original)
	if !site.Advanced.Protection.SemanticNoSQL {
		t.Fatalf("expected storage site to preserve NoSQL semantic switch: %+v", site.Advanced.Protection)
	}
	if !site.Advanced.Protection.SemanticSSTI {
		t.Fatalf("expected storage site to preserve SSTI semantic switch: %+v", site.Advanced.Protection)
	}
	converted := SiteToConfig(site)
	if !converted.WAF.SemanticEngines.NoSQL {
		t.Fatalf("expected config site to preserve NoSQL semantic switch: %+v", converted.WAF.SemanticEngines)
	}
	if !converted.WAF.SemanticEngines.SSTI {
		t.Fatalf("expected config site to preserve SSTI semantic switch: %+v", converted.WAF.SemanticEngines)
	}
}
