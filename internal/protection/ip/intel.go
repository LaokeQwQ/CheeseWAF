package ip

import (
	"net"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Indicator struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	Labels    []string  `json:"labels"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type Intel struct {
	items []indicatorMatcher
	now   func() time.Time
}

type indicatorMatcher struct {
	indicator Indicator
	ip        net.IP
	network   *net.IPNet
}

func NewIntel(configs []config.ThreatIntelConfig) (*Intel, error) {
	intel := &Intel{now: time.Now}
	for _, item := range configs {
		if !item.Enabled || strings.TrimSpace(item.Value) == "" {
			continue
		}
		matcher := indicatorMatcher{
			indicator: Indicator{
				ID:        item.ID,
				Value:     strings.TrimSpace(item.Value),
				Type:      empty(item.Type, "ip"),
				Severity:  strings.ToLower(empty(item.Severity, "medium")),
				Source:    item.Source,
				Labels:    append([]string(nil), item.Labels...),
				ExpiresAt: item.ExpiresAt,
			},
		}
		if strings.Contains(item.Value, "/") {
			_, network, err := net.ParseCIDR(item.Value)
			if err != nil {
				return nil, err
			}
			matcher.network = network
		} else if parsed := net.ParseIP(item.Value); parsed != nil {
			matcher.ip = parsed
		}
		intel.items = append(intel.items, matcher)
	}
	return intel, nil
}

func (i *Intel) Match(raw string) []Indicator {
	if i == nil {
		return nil
	}
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil {
		return nil
	}
	var out []Indicator
	now := i.now().UTC()
	for _, item := range i.items {
		if !item.indicator.ExpiresAt.IsZero() && item.indicator.ExpiresAt.Before(now) {
			continue
		}
		if item.ip != nil && item.ip.Equal(parsed) {
			out = append(out, item.indicator)
			continue
		}
		if item.network != nil && item.network.Contains(parsed) {
			out = append(out, item.indicator)
		}
	}
	return out
}

func (i *Intel) Values() []Indicator {
	if i == nil {
		return nil
	}
	out := make([]Indicator, 0, len(i.items))
	now := i.now().UTC()
	for _, item := range i.items {
		if !item.indicator.ExpiresAt.IsZero() && item.indicator.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, item.indicator)
	}
	return out
}

func empty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
