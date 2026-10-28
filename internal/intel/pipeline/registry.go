package pipeline

import (
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
)

// SourceConfig is the operator-facing registration for one feed. Trust is a
// string so configuration stays independent of the feed package; it must be
// one of official, vendor, community, or unknown (or empty for unknown).
type SourceConfig struct {
	ID      string
	Name    string
	URL     string
	Format  string // rss, atom, json; empty auto-detects
	Trust   string
	Enabled bool
}

// Registry adapts an allowlisted feed registry to the intel trust model. It
// performs no network I/O and keeps the feed and intel views of every source
// in sync.
type Registry struct {
	feeds *feed.SourceRegistry
	intel []intel.Source
}

// NewRegistry validates and registers every source. Unknown trust values are
// rejected rather than silently downgraded to unknown.
func NewRegistry(configs []SourceConfig) (*Registry, error) {
	feedSources := make([]feed.Source, 0, len(configs))
	for index, config := range configs {
		trust, err := parseSourceTrust(config.Trust)
		if err != nil {
			return nil, fmt.Errorf("%w: source %d: %w", ErrInvalid, index, err)
		}
		source := feed.Source{
			ID:      config.ID,
			Name:    config.Name,
			URL:     config.URL,
			Trust:   trust,
			Enabled: config.Enabled,
		}
		if strings.TrimSpace(config.Format) != "" {
			format := feed.ParseFormat(config.Format)
			if format == "" {
				return nil, fmt.Errorf("%w: source %q has unknown format %q", ErrInvalid, config.ID, config.Format)
			}
			source.Format = format
		}
		feedSources = append(feedSources, source)
	}

	feeds, err := feed.NewSourceRegistry(feedSources)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	registered := feeds.Sources()
	sources := make([]intel.Source, 0, len(registered))
	for _, source := range registered {
		sources = append(sources, intel.Source{
			ID:      source.ID,
			Type:    intelSourceType(source.Format),
			URL:     source.URL,
			Trust:   mapTrustLevel(source.Trust),
			Enabled: source.Enabled,
		})
	}
	return &Registry{feeds: feeds, intel: sources}, nil
}

// Resolve returns an enabled feed source by ID.
func (r *Registry) Resolve(id string) (feed.Source, error) {
	if r == nil || r.feeds == nil {
		return feed.Source{}, fmt.Errorf("%w: registry is not configured", ErrInvalid)
	}
	return r.feeds.Resolve(id)
}

// IntelSources returns a copy of the sources in the intel trust model, sorted
// by source ID.
func (r *Registry) IntelSources() []intel.Source {
	if r == nil {
		return nil
	}
	out := make([]intel.Source, len(r.intel))
	copy(out, r.intel)
	return out
}

func parseSourceTrust(raw string) (feed.TrustLevel, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return feed.TrustUnknown, nil
	}
	trust := feed.ParseTrustLevel(trimmed)
	if !trust.Valid() || !strings.EqualFold(trimmed, string(trust)) {
		return "", fmt.Errorf("trust must be official, vendor, community, or unknown, got %q", raw)
	}
	return trust, nil
}

// mapTrustLevel is intentionally explicit: feed and intel define separate
// enum types and must not be converted by string cast.
func mapTrustLevel(trust feed.TrustLevel) intel.TrustLevel {
	switch trust {
	case feed.TrustOfficial:
		return intel.TrustOfficial
	case feed.TrustVendor:
		return intel.TrustVendor
	case feed.TrustCommunity:
		return intel.TrustCommunity
	default:
		return intel.TrustUnknown
	}
}

func intelSourceType(format feed.Format) string {
	switch format {
	case feed.FormatRSS:
		return "rss"
	case feed.FormatAtom:
		return "atom"
	case feed.FormatJSON:
		return "api"
	default:
		return "url"
	}
}
