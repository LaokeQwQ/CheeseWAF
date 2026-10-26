package intel

import "testing"

func enabledSource(id string, trust TrustLevel) Source {
	return Source{ID: id, Type: "rss", URL: "https://example.test/feed", Trust: trust, Enabled: true}
}

func TestTrustPolicyEvaluateSources(t *testing.T) {
	policy := DefaultTrustPolicy()
	tests := []struct {
		name       string
		sources    []Source
		wantAllow  bool
		wantTrust  TrustLevel
		wantReason string
	}{
		{
			name:      "official single source",
			sources:   []Source{enabledSource("feed-official", TrustOfficial)},
			wantAllow: true,
			wantTrust: TrustOfficial,
		},
		{
			name:      "vendor single source",
			sources:   []Source{enabledSource("feed-vendor", TrustVendor)},
			wantAllow: true,
			wantTrust: TrustVendor,
		},
		{
			name:       "community single source quarantined",
			sources:    []Source{enabledSource("feed-community", TrustCommunity)},
			wantReason: "community source needs at least 2 independent enabled sources, got 1",
		},
		{
			name:      "community corroborated",
			sources:   []Source{enabledSource("feed-a", TrustCommunity), enabledSource("feed-b", TrustCommunity)},
			wantAllow: true,
			wantTrust: TrustCommunity,
		},
		{
			name:       "unknown single source quarantined",
			sources:    []Source{enabledSource("feed-unknown", TrustUnknown)},
			wantReason: "unknown source must be allowlisted before it can yield candidates (1 unknown sources)",
		},
		{
			name:       "unknown sources are never sufficient",
			sources:    []Source{enabledSource("feed-x", TrustUnknown), enabledSource("feed-y", TrustUnknown)},
			wantReason: "unknown source must be allowlisted before it can yield candidates (2 unknown sources)",
		},
		{
			name:       "community plus unknown is not corroborated",
			sources:    []Source{enabledSource("feed-a", TrustCommunity), enabledSource("feed-x", TrustUnknown)},
			wantReason: "community source needs at least 2 independent enabled sources, got 1",
		},
		{
			name:      "vendor dominates community",
			sources:   []Source{enabledSource("feed-a", TrustCommunity), enabledSource("feed-v", TrustVendor)},
			wantAllow: true,
			wantTrust: TrustVendor,
		},
		{
			name:       "disabled sources are ignored",
			sources:    []Source{{ID: "feed-official", Type: "rss", Trust: TrustOfficial, Enabled: false}},
			wantReason: "no enabled sources reported this item",
		},
		{
			name: "duplicate ids count once",
			sources: []Source{
				enabledSource("feed-a", TrustCommunity),
				enabledSource("feed-a", TrustCommunity),
			},
			wantReason: "community source needs at least 2 independent enabled sources, got 1",
		},
		{name: "no sources", sources: nil, wantReason: "no enabled sources reported this item"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := policy.EvaluateSources(test.sources)
			if decision.Allowed != test.wantAllow {
				t.Fatalf("allowed=%v, want %v (reason %q)", decision.Allowed, test.wantAllow, decision.Reason)
			}
			if decision.Quarantined == test.wantAllow {
				t.Fatalf("unexpected quarantine flag: %+v", decision)
			}
			if test.wantAllow && decision.Trust != test.wantTrust {
				t.Fatalf("trust=%q, want %q", decision.Trust, test.wantTrust)
			}
			if test.wantReason != "" && decision.Reason != test.wantReason {
				t.Fatalf("reason=%q, want %q", decision.Reason, test.wantReason)
			}
		})
	}
}

func TestTrustPolicyEvaluateItemResolvesRegistry(t *testing.T) {
	registry := []Source{
		enabledSource("feed-a", TrustCommunity),
		enabledSource("feed-b", TrustCommunity),
		enabledSource("feed-v", TrustVendor),
		{ID: "feed-disabled", Type: "rss", Trust: TrustOfficial, Enabled: false},
	}
	item := Item{ID: "item-1", SourceID: "feed-a", CorroboratingSourceIDs: []string{"feed-b"}}
	decision := DefaultTrustPolicy().EvaluateItem(item, registry)
	if !decision.Allowed || decision.Trust != TrustCommunity {
		t.Fatalf("expected corroborated community item to be allowed: %+v", decision)
	}
	if decision.IndependentSources != 2 {
		t.Fatalf("expected 2 independent sources, got %d", decision.IndependentSources)
	}

	unknown := Item{ID: "item-2", SourceID: "feed-unknown"}
	decision = DefaultTrustPolicy().EvaluateItem(unknown, registry)
	if decision.Allowed || !decision.Quarantined {
		t.Fatalf("expected unregistered source to be quarantined: %+v", decision)
	}

	disabled := Item{ID: "item-3", SourceID: "feed-disabled"}
	decision = DefaultTrustPolicy().EvaluateItem(disabled, registry)
	if decision.Allowed || !decision.Quarantined {
		t.Fatalf("expected disabled source to be quarantined: %+v", decision)
	}

	corroboratedByVendor := Item{
		ID:                     "item-4",
		SourceID:               "feed-unknown",
		CorroboratingSourceIDs: []string{"feed-v"},
	}
	decision = DefaultTrustPolicy().EvaluateItem(corroboratedByVendor, registry)
	if !decision.Allowed || decision.Trust != TrustVendor {
		t.Fatalf("expected vendor corroboration to allow the item: %+v", decision)
	}
}
