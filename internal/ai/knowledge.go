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
	for _, item := range []string{"waf", "规则", "拦截", "误报", "漏报", "语义", "置信度", "防护等级", "验证码", "bot", "ai", "自学习", "ssl", "证书", "acme", "ip", "情报", "日志", "事件", "api", "token", "令牌", "rbac", "scope", "权限", "审计", "审批", "streaming", "reasoning", "流式", "思考", "超时", "缓存", "压缩"} {
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
		{ID: "semantic-confidence-levels", Title: "Semantic confidence and protection levels", Tags: []string{"semantic", "confidence", "protection level", "语义", "置信度", "防护等级", "误报"}, Content: "Semantic detections must keep confidence visible. Low-confidence or ambiguous evidence should log, monitor, or challenge before blocking. The default smart level favors business continuity and lower false positives; high and strict lower thresholds only when severity and semantic evidence are strong and auditable."},
		{ID: "waf-api-token-management", Title: "WAF API token management", Tags: []string{"api", "token", "令牌", "rbac", "scope", "权限", "audit", "审计"}, Content: "Console API access should be explicitly enabled, create scoped tokens with one-time visible secrets, store only hashes, support revoke/rotation/expiry, and reuse the same RBAC permission matrix as Web users. Token usage should be audited and must not bypass AI approval boundaries or sensitive configuration checks."},
		{ID: "ai-streaming-approval-readiness", Title: "AI streaming, approvals, and long reasoning", Tags: []string{"ai", "streaming", "reasoning", "流式", "思考", "审批", "timeout", "超时"}, Content: "Assistant and single-event analysis should stream provider-visible reasoning, content deltas, tool calls, approval states, and heartbeat/progress events separately. Long reasoning is allowed up to the server AI timeout; the UI should show ongoing status instead of treating delayed first tokens as final-response timeout."},
		{ID: "cluster-ha-readiness", Title: "Cluster and high availability readiness", Tags: []string{"cluster", "ha", "集群", "高可用", "防数据偏差"}, Content: "Standalone mode is the default. Multi-node expansion must use mTLS node identity, one-time join tokens, health monitoring, data-divergence protection, and write-freezing during unsafe states before it can be described as production HA traffic scheduling."},
		{ID: "captcha-product-flow", Title: "CAPTCHA and secure entry flow", Tags: []string{"captcha", "验证码", "slider", "滑块", "bot"}, Content: "Admin login verification and visitor Bot challenge are separate products. CAPTCHA should use real server-verified tokens, randomized puzzle/image/audio or proof-of-work modes, clear success/failure states, replay prevention, and mobile-friendly fallback."},
	}
}
