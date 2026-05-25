package ip

import (
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type ReputationProfile struct {
	IP         string         `json:"ip"`
	List       string         `json:"list"`
	Reputation int            `json:"reputation"`
	Tags       []string       `json:"tags"`
	Intel      []Indicator    `json:"intel"`
	Stats      ReputationStat `json:"stats"`
}

type ReputationStat struct {
	Total   int            `json:"total"`
	Blocked int            `json:"blocked"`
	ByType  map[string]int `json:"by_type"`
}

func BuildReputationProfiles(cfg config.IPProtectionConfig, entries []storage.LogEntry) ([]ReputationProfile, error) {
	whitelist, err := NewMatcher(cfg.Whitelist)
	if err != nil {
		return nil, err
	}
	blacklist, err := NewMatcher(cfg.Blacklist)
	if err != nil {
		return nil, err
	}
	intel, err := NewIntel(cfg.ThreatIntel)
	if err != nil {
		return nil, err
	}
	tagger := NewTagger(cfg.Tags)
	stats := map[string]ReputationStat{}
	keys := map[string]struct{}{}
	addKeys(keys, cfg.Whitelist)
	addKeys(keys, cfg.Blacklist)
	for key := range cfg.Tags {
		keys[key] = struct{}{}
	}
	for _, indicator := range intel.Values() {
		keys[indicator.Value] = struct{}{}
	}
	for _, entry := range entries {
		if strings.TrimSpace(entry.ClientIP) == "" {
			continue
		}
		keys[entry.ClientIP] = struct{}{}
		stat := stats[entry.ClientIP]
		if stat.ByType == nil {
			stat.ByType = map[string]int{}
		}
		stat.Total++
		if entry.Action == "block" {
			stat.Blocked++
		}
		if entry.Category != "" {
			stat.ByType[entry.Category]++
		}
		stats[entry.ClientIP] = stat
	}
	profiles := make([]ReputationProfile, 0, len(keys))
	for key := range keys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		stat := stats[key]
		if stat.ByType == nil {
			stat.ByType = map[string]int{}
		}
		profile := ReputationProfile{
			IP:    key,
			List:  listName(key, whitelist, blacklist),
			Tags:  tagger.Tags(key),
			Intel: intel.Match(key),
			Stats: stat,
		}
		profile.Reputation = score(profile)
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].Reputation == profiles[j].Reputation {
			return profiles[i].IP < profiles[j].IP
		}
		return profiles[i].Reputation < profiles[j].Reputation
	})
	return profiles, nil
}

func addKeys(keys map[string]struct{}, values []string) {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			keys[value] = struct{}{}
		}
	}
}

func listName(raw string, whitelist, blacklist *Matcher) string {
	switch {
	case whitelist.Contains(raw):
		return "whitelist"
	case blacklist.Contains(raw):
		return "blacklist"
	default:
		return "monitor"
	}
}

func score(profile ReputationProfile) int {
	if profile.List == "whitelist" {
		return 100
	}
	value := 80
	if profile.List == "blacklist" {
		value = 10
	}
	value -= min(profile.Stats.Blocked*5, 50)
	for _, tag := range profile.Tags {
		switch tag {
		case "rce", "sqli", "webshell", "abuse":
			value -= 18
		case "bot", "repeat", "scanner":
			value -= 10
		}
	}
	for _, indicator := range profile.Intel {
		switch indicator.Severity {
		case "critical":
			value -= 70
		case "high":
			value -= 45
		case "medium":
			value -= 25
		default:
			value -= 10
		}
	}
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
