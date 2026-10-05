package ai

import (
	_ "embed"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type KnowledgeSnippet struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Content string   `json:"content"`
	Tags    []string `json:"tags"`
}

type KnowledgeBase struct {
	enabled     bool
	maxSnippets int
	snippets    []KnowledgeSnippet
}

// knowledgeDefaultJSON is deliberately kept as an editable data asset rather
// than a Go string literal. Operators can replace it with AI.Knowledge.File
// without rebuilding CheeseWAF.
//
//go:embed knowledge.default.json
var knowledgeDefaultJSON []byte

func NewKnowledgeBase(cfg config.AIKnowledgeConfig) *KnowledgeBase {
	if !cfg.Enabled {
		return &KnowledgeBase{}
	}
	maxSnippets := cfg.MaxSnippets
	if maxSnippets <= 0 {
		maxSnippets = 5
	}
	snippets := []KnowledgeSnippet{}
	if cfg.Builtin {
		snippets = decodeKnowledgeJSON(knowledgeDefaultJSON)
	}
	if path := strings.TrimSpace(cfg.File); path != "" {
		if raw, err := os.ReadFile(path); err == nil && len(raw) <= 2<<20 {
			if custom := decodeKnowledgeJSON(raw); len(custom) > 0 {
				snippets = custom
			}
		}
	}
	return &KnowledgeBase{enabled: true, maxSnippets: maxSnippets, snippets: snippets}
}

func decodeKnowledgeJSON(raw []byte) []KnowledgeSnippet {
	var snippets []KnowledgeSnippet
	if err := json.Unmarshal(raw, &snippets); err != nil {
		return nil
	}
	valid := make([]KnowledgeSnippet, 0, len(snippets))
	seen := map[string]struct{}{}
	for _, snippet := range snippets {
		snippet.ID = strings.TrimSpace(snippet.ID)
		snippet.Title = strings.TrimSpace(snippet.Title)
		snippet.Content = strings.TrimSpace(snippet.Content)
		if snippet.ID == "" || snippet.Title == "" || snippet.Content == "" {
			continue
		}
		if _, exists := seen[snippet.ID]; exists {
			continue
		}
		seen[snippet.ID] = struct{}{}
		cleanTags := make([]string, 0, len(snippet.Tags))
		for _, tag := range snippet.Tags {
			if tag = strings.TrimSpace(tag); tag != "" {
				cleanTags = append(cleanTags, tag)
			}
		}
		snippet.Tags = cleanTags
		valid = append(valid, snippet)
	}
	return valid
}

func (kb *KnowledgeBase) Search(query string, limit int) []KnowledgeSnippet {
	if kb == nil || !kb.enabled {
		return nil
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	if limit <= 0 || limit > kb.maxSnippets {
		limit = kb.maxSnippets
	}
	type scored struct {
		item  KnowledgeSnippet
		score int
	}
	var matches []scored
	terms := knowledgeTerms(query)
	for _, item := range kb.snippets {
		haystack := strings.ToLower(item.Title + "\n" + item.Content + "\n" + strings.Join(item.Tags, " "))
		score := 0
		for _, term := range terms {
			if strings.Contains(haystack, term) {
				score++
			}
		}
		if score > 0 {
			matches = append(matches, scored{item: item, score: score})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score == matches[j].score {
			return matches[i].item.ID < matches[j].item.ID
		}
		return matches[i].score > matches[j].score
	})
	out := make([]KnowledgeSnippet, 0, min(len(matches), limit))
	for _, match := range matches {
		out = append(out, match.item)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (kb *KnowledgeBase) SearchJSON(query string, limit int) string {
	items := kb.Search(query, limit)
	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func knowledgeTerms(query string) []string {
	raw := strings.FieldsFunc(query, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == '，' || r == '?' || r == '？' || r == '/' || r == '、'
	})
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, term := range raw {
		term = strings.ToLower(strings.TrimSpace(term))
		if len([]rune(term)) < 2 {
			continue
		}
		if _, ok := seen[term]; ok {
			continue
		}
		seen[term] = struct{}{}
		out = append(out, term)
	}
	return out
}
