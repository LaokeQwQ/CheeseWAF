package intel

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultRequiredCorroboration is the minimum number of independent enabled
// sources required for community intelligence.
const DefaultRequiredCorroboration = 2

// TrustPolicy decides whether intelligence may yield candidates. Official and
// vendor sources may yield a candidate on their own. Community sources need
// corroboration from independent enabled sources. Unknown sources are always
// quarantined until an operator allowlists them.
type TrustPolicy struct {
	RequiredCorroboration int
}

// DefaultTrustPolicy uses two-source corroboration for community intelligence.
func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{RequiredCorroboration: DefaultRequiredCorroboration}
}

// TrustDecision is a deterministic audit record for one item.
type TrustDecision struct {
	Allowed            bool
	Quarantined        bool
	Trust              TrustLevel
	IndependentSources int
	SourceIDs          []string
	Reason             string
}

// EvaluateItem resolves the item's primary and corroborating source IDs against
// the registered source list and evaluates the resulting sources.
func (p TrustPolicy) EvaluateItem(item Item, registry []Source) TrustDecision {
	byID := make(map[string]Source, len(registry))
	for _, source := range registry {
		id := strings.TrimSpace(source.ID)
		if id == "" {
			continue
		}
		if _, exists := byID[id]; !exists {
			byID[id] = source
		}
	}
	ids := make([]string, 0, 1+len(item.CorroboratingSourceIDs))
	seen := make(map[string]struct{}, 1+len(item.CorroboratingSourceIDs))
	for _, id := range append([]string{item.SourceID}, item.CorroboratingSourceIDs...) {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sources := make([]Source, 0, len(ids))
	for _, id := range ids {
		source, ok := byID[id]
		if !ok {
			source = Source{ID: id, Trust: TrustUnknown, Enabled: true}
		}
		sources = append(sources, source)
	}
	return p.EvaluateSources(sources)
}

// EvaluateSources applies the trust policy to the enabled sources that reported
// an item. Duplicate IDs count once; disabled sources are ignored.
func (p TrustPolicy) EvaluateSources(sources []Source) TrustDecision {
	required := p.RequiredCorroboration
	if required < DefaultRequiredCorroboration {
		required = DefaultRequiredCorroboration
	}
	seen := make(map[string]Source, len(sources))
	for _, source := range sources {
		id := strings.TrimSpace(source.ID)
		if id == "" || !source.Enabled {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = source
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	decision := TrustDecision{IndependentSources: len(seen), SourceIDs: ids}
	if len(seen) == 0 {
		decision.Quarantined = true
		decision.Trust = TrustUnknown
		decision.Reason = "no enabled sources reported this item"
		return decision
	}
	highest := TrustUnknown
	community := 0
	unknown := 0
	for _, id := range ids {
		trust := ParseTrustLevel(string(seen[id].Trust))
		if trust.Rank() > highest.Rank() {
			highest = trust
		}
		switch trust {
		case TrustCommunity:
			community++
		case TrustOfficial, TrustVendor:
			// The highest-ranked source is enough.
		default:
			unknown++
		}
	}
	decision.Trust = highest
	switch highest {
	case TrustOfficial, TrustVendor:
		decision.Allowed = true
		decision.Reason = fmt.Sprintf("%s source may yield candidates", highest)
		return decision
	}
	if community >= required {
		decision.Allowed = true
		decision.Reason = fmt.Sprintf("community intelligence corroborated by %d independent sources", community)
		return decision
	}
	decision.Quarantined = true
	if community > 0 {
		decision.Reason = fmt.Sprintf("community source needs at least %d independent enabled sources, got %d", required, community)
		return decision
	}
	decision.Reason = fmt.Sprintf("unknown source must be allowlisted before it can yield candidates (%d unknown sources)", unknown)
	return decision
}
