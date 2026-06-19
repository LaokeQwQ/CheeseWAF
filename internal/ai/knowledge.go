package ai

import (
	"encoding/json"
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

func NewKnowledgeBase(cfg config.AIKnowledgeConfig) *KnowledgeBase {
	if !cfg.Enabled || !cfg.Builtin {
		return &KnowledgeBase{}
	}
	maxSnippets := cfg.MaxSnippets
	if maxSnippets <= 0 {
		maxSnippets = 5
	}
	return &KnowledgeBase{enabled: true, maxSnippets: maxSnippets, snippets: builtinKnowledgeSnippets()}
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
	for _, item := range []string{"waf", "规则", "拦截", "误报", "漏报", "语义", "验证码", "bot", "ai", "自学习", "ssl", "证书", "acme", "ip", "情报", "日志", "事件", "api", "缓存", "压缩"} {
		if strings.Contains(query, item) {
			raw = append(raw, item)
		}
	}
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

func builtinKnowledgeSnippets() []KnowledgeSnippet {
	return []KnowledgeSnippet{
		{ID: "waf-policy-levels", Title: "Protection levels", Tags: []string{"waf", "policy", "规则", "防护等级"}, Content: "CheeseWAF uses site-first protection levels. Site settings override global defaults; path and API-specific rules belong in advanced/custom rules. Smart mode prioritizes low false positives, while strict mode raises sensitivity and should be verified with traffic baselines."},
		{ID: "ai-self-learning", Title: "AI self-learning guardrails", Tags: []string{"ai", "自学习", "规则"}, Content: "Self-learning reads real blocked, challenged, and logged security events. It can dry-run by default and should auto-apply only repeated high-confidence, narrow patterns that compile and are not broad business paths or normal parameters."},
		{ID: "event-analysis", Title: "Event analysis workflow", Tags: []string{"ai", "事件", "日志", "analysis"}, Content: "Event analysis should use the event or trace ID to load real log evidence first. The final answer should explain attack type, evidence, impact, recommended action, and false-positive considerations without exposing hidden prompts or tool-call mechanics."},
		{ID: "bot-challenge", Title: "Bot verification", Tags: []string{"bot", "captcha", "验证码", "challenge"}, Content: "Bot verification supports proof-of-work, image CAPTCHA, and slider CAPTCHA. Admin login verification is separate from WAF-side visitor challenge policies. Changing challenge settings is a modifying action and requires operator approval when done through the AI assistant."},
		{ID: "ip-intelligence", Title: "IP intelligence and access lists", Tags: []string{"ip", "情报", "黑名单", "白名单"}, Content: "IP access controls should distinguish global, site, and path scopes. CDN deployments need trusted real-IP headers such as X-Forwarded-For and X-Real-IP. Threat intelligence imports should preserve source, confidence, labels, action, expiry, and notes."},
		{ID: "acme-flow", Title: "ACME certificate pipeline", Tags: []string{"ssl", "acme", "证书"}, Content: "ACME automation should guide DNS provider selection, DNS TXT creation, issuance, certificate deployment, DNS cleanup, service reload, and notification. Secrets belong in server runtime configuration and should never be exposed in UI responses."},
		{ID: "edge-cache-compression", Title: "Edge cache, headers, and compression", Tags: []string{"缓存", "压缩", "header", "edge"}, Content: "Header rules should support set, append, and remove operations. Cache policies need TTL with units, status-code scope, body-size limits, and path filters. Compression should expose algorithms such as gzip, brotli, and zstd when supported, with level and minimum body-size controls."},
	}
}
