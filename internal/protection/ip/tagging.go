package ip

import (
	"sort"
	"strings"
)

type Tagger struct {
	tags map[string][]string
}

func NewTagger(tags map[string][]string) *Tagger {
	copied := map[string][]string{}
	for key, values := range tags {
		copied[strings.TrimSpace(key)] = normalizeTags(values)
	}
	return &Tagger{tags: copied}
}

func (t *Tagger) Tags(raw string) []string {
	if t == nil {
		return []string{}
	}
	values := t.tags[strings.TrimSpace(raw)]
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func (t *Tagger) Set(raw string, tags []string) {
	if t == nil {
		return
	}
	key := strings.TrimSpace(raw)
	if key == "" {
		return
	}
	normalized := normalizeTags(tags)
	if len(normalized) == 0 {
		delete(t.tags, key)
		return
	}
	t.tags[key] = normalized
}

func (t *Tagger) Snapshot() map[string][]string {
	out := map[string][]string{}
	if t == nil {
		return out
	}
	for key, values := range t.tags {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func normalizeTags(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			tag := strings.ToLower(strings.TrimSpace(part))
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return out
}
