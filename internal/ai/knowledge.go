package ai

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

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
	searchable  []string
}

// knowledgeDefaultJSON is deliberately kept as an editable data asset rather
// than a Go string literal. Operators can replace it with AI.Knowledge.File
// without rebuilding CheeseWAF.
//
//go:embed knowledge.default.json
var knowledgeDefaultJSON []byte

func NewKnowledgeBase(cfg config.AIKnowledgeConfig) *KnowledgeBase {
	var raw []byte
	if path := strings.TrimSpace(cfg.File); cfg.Enabled && path != "" {
		var err error
		raw, err = readKnowledgeFile(path)
		if err != nil {
			logKnowledgeFileFailure()
		}
	}
	return newKnowledgeBase(cfg, raw)
}

func newKnowledgeBase(cfg config.AIKnowledgeConfig, raw []byte) *KnowledgeBase {
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
	if custom := decodeKnowledgeJSON(raw); len(custom) > 0 {
		snippets = custom
	}
	kb := &KnowledgeBase{enabled: true, maxSnippets: min(maxSnippets, 10), snippets: snippets}
	for _, item := range snippets {
		kb.searchable = append(kb.searchable, strings.ToLower(item.Title+"\n"+item.Content+"\n"+strings.Join(item.Tags, " ")))
	}
	return kb
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
	if len(query) > 4096 {
		query = query[:4096]
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
	for index, item := range kb.snippets {
		haystack := kb.searchable[index]
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
		out[len(out)-1].Tags = append([]string(nil), match.item.Tags...)
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
		if len(out) == 32 {
			break
		}
	}
	return out
}

const maxKnowledgeFileBytes = 2 << 20

func logKnowledgeFileFailure() {
	// OS errors can contain administrator paths; keep diagnostics bounded and
	// independent of both the configured path and the knowledge contents.
	log.Print("ai knowledge: custom source could not be loaded; check AI.Knowledge.File is readable, regular, not a symlink, and at most 2 MiB; using configured builtin/empty fallback")
}

func readKnowledgeFile(path string) ([]byte, error) {
	f, _, err := openValidatedKnowledgeFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readOpenedKnowledgeFile(f)
}

func openValidatedKnowledgeFile(path string) (*os.File, os.FileInfo, error) {
	// Lstat rejects devices, FIFOs, and symlinks before opening (which could block).
	info, err := statKnowledgeFile(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxKnowledgeFileBytes {
		return nil, nil, fmt.Errorf("knowledge source must be a regular file of at most 2 MiB")
	}
	f, err := openKnowledgeFile(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > maxKnowledgeFileBytes || !os.SameFile(info, opened) {
		f.Close()
		return nil, nil, fmt.Errorf("knowledge source changed while opening")
	}
	return f, opened, nil
}

func readOpenedKnowledgeFile(f *os.File) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(f, maxKnowledgeFileBytes+1))
	if len(raw) > maxKnowledgeFileBytes {
		return nil, fmt.Errorf("knowledge source exceeds 2 MiB")
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

var knowledgeCache struct {
	sync.Mutex
	config config.AIKnowledgeConfig
	base   *KnowledgeBase
	file   os.FileInfo
}

// CachedKnowledgeBase publishes an immutable snapshot until the configuration or
// knowledge file identity, size, modification time, or mode changes.
func CachedKnowledgeBase(cfg config.AIKnowledgeConfig) *KnowledgeBase {
	knowledgeCache.Lock()
	defer knowledgeCache.Unlock()
	var info os.FileInfo
	var f *os.File
	var loadErr error
	if path := strings.TrimSpace(cfg.File); cfg.Enabled && path != "" {
		// Stat the open handle: Windows Lstat file IDs are resolved lazily from
		// the path, which may already name a replacement at the next cache lookup.
		f, info, loadErr = openValidatedKnowledgeFile(path)
		if f != nil {
			defer f.Close()
		}
	}
	changed := (info == nil) != (knowledgeCache.file == nil)
	if info != nil && knowledgeCache.file != nil {
		changed = !os.SameFile(info, knowledgeCache.file) || info.Size() != knowledgeCache.file.Size() || info.ModTime() != knowledgeCache.file.ModTime() || info.Mode() != knowledgeCache.file.Mode()
	}
	if knowledgeCache.base == nil || knowledgeCache.config != cfg || changed {
		var raw []byte
		if cfg.Enabled && f != nil {
			raw, loadErr = readOpenedKnowledgeFile(f)
		}
		if loadErr != nil {
			logKnowledgeFileFailure()
		}
		knowledgeCache.config = cfg
		knowledgeCache.base = newKnowledgeBase(cfg, raw)
		knowledgeCache.file = info
	}
	return knowledgeCache.base
}
