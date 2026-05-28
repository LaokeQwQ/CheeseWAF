package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type AttackAnalysis struct {
	LogID              string   `json:"log_id"`
	Risk               string   `json:"risk"`
	Summary            string   `json:"summary"`
	Evidence           []string `json:"evidence"`
	EventType          string   `json:"event_type"`
	AIUsed             bool     `json:"ai_used"`
	RecommendedActions []string `json:"recommended_actions"`
}

type AssistantReply struct {
	Answer    string   `json:"answer"`
	AIUsed    bool     `json:"ai_used"`
	LogIDs    []string `json:"log_ids"`
	Events    int      `json:"events"`
	Blocked   int      `json:"blocked"`
	Challenge int      `json:"challenge"`
}

func AnalyzeLog(ctx context.Context, client *Client, entry storage.LogEntry) (*AttackAnalysis, error) {
	base := HeuristicAnalysis(entry)
	if client == nil {
		return base, nil
	}
	content, err := client.Complete(ctx, []Message{
		{Role: "system", Content: "You are a concise WAF analyst. Return a short incident summary and concrete mitigations."},
		{Role: "user", Content: fmt.Sprintf("Analyze this WAF log: category=%s action=%s status=%d uri=%s ua=%s message=%s payload=%s", entry.Category, entry.Action, entry.StatusCode, entry.URI, entry.UserAgent, entry.Message, entry.Payload)},
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(content) != "" {
		base.Summary = content
		base.AIUsed = true
	}
	return base, nil
}

func AnalyzeEvents(ctx context.Context, client *Client, entries []storage.LogEntry) ([]AttackAnalysis, error) {
	out := make([]AttackAnalysis, 0, len(entries))
	for _, entry := range entries {
		if !isSecurityEvent(entry) {
			continue
		}
		analysis, err := AnalyzeLog(ctx, client, entry)
		if err != nil {
			return nil, err
		}
		out = append(out, *analysis)
	}
	return out, nil
}

func AnswerAssistant(ctx context.Context, client *Client, question string, entries []storage.LogEntry, runtimeSummary map[string]any) (*AssistantReply, error) {
	events := securityEvents(entries)
	reply := heuristicAssistantReply(question, events)
	reply.Events = len(events)
	for _, entry := range events {
		reply.LogIDs = append(reply.LogIDs, entry.ID)
		switch strings.ToLower(entry.Action) {
		case "block":
			reply.Blocked++
		case "challenge":
			reply.Challenge++
		}
	}
	if client == nil {
		return reply, nil
	}
	contextBody, err := json.Marshal(map[string]any{
		"runtime": runtimeSummary,
		"events":  compactEvents(events, 20),
	})
	if err != nil {
		return nil, err
	}
	content, err := client.Complete(ctx, []Message{
		{Role: "system", Content: "You are CheeseWAF's security operations assistant. Answer only from the provided real monitor and WAF event context. If data is missing, say what is missing. Focus on actionable WAF operations."},
		{Role: "user", Content: "Question: " + question + "\nReal context JSON:\n" + string(contextBody)},
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(content) != "" {
		reply.Answer = content
		reply.AIUsed = true
	}
	return reply, nil
}

func HeuristicAnalysis(entry storage.LogEntry) *AttackAnalysis {
	risk := "low"
	if entry.Action == "block" {
		risk = "medium"
	}
	switch strings.ToLower(entry.Severity) {
	case "critical":
		risk = "critical"
	case "high":
		risk = "high"
	}
	if risk != "critical" && isHighSignalCategory(entry.Category) {
		risk = "high"
	}
	category := entry.Category
	if category == "" {
		category = "unknown"
	}
	actions := []string{
		"Review adjacent requests from the same source IP.",
		"Confirm the matched rule and reduce false positives before tightening policy.",
	}
	if entry.ClientIP != "" {
		actions = append(actions, "Tag or block the source IP if repeated attempts continue.")
	}
	return &AttackAnalysis{
		LogID:              entry.ID,
		Risk:               risk,
		Summary:            fmt.Sprintf("%s request from %s matched %s on %s and was %s.", entry.Method, emptyAsUnknown(entry.ClientIP), category, emptyAsUnknown(entry.URI), emptyAs(entry.Action, "logged")),
		Evidence:           eventEvidence(entry),
		EventType:          eventType(entry),
		AIUsed:             false,
		RecommendedActions: actions,
	}
}

func eventEvidence(entry storage.LogEntry) []string {
	evidence := make([]string, 0, 8)
	add := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			evidence = append(evidence, label+": "+value)
		}
	}
	add("TraceID", entry.TraceID)
	add("Action", entry.Action)
	add("Category", entry.Category)
	add("Severity", entry.Severity)
	add("Detector", entry.DetectorID)
	add("URI", entry.URI)
	add("Payload", entry.Payload)
	add("User-Agent", entry.UserAgent)
	if entry.StatusCode > 0 {
		evidence = append(evidence, fmt.Sprintf("Status: %d", entry.StatusCode))
	}
	return evidence
}

func eventType(entry storage.LogEntry) string {
	switch strings.ToLower(entry.Action) {
	case "block":
		return "blocked_attack"
	case "challenge":
		return "challenged_request"
	case "log":
		return "logged_attack"
	default:
		if strings.TrimSpace(entry.Category) != "" {
			return "detected_event"
		}
		return "access_event"
	}
}

func isHighSignalCategory(category string) bool {
	switch strings.ToLower(category) {
	case "sqli", "sql", "rce", "xxe", "ssrf", "webshell":
		return true
	default:
		return false
	}
}

func isSecurityEvent(entry storage.LogEntry) bool {
	return strings.TrimSpace(entry.Category) != "" || entry.Action == "block" || entry.Action == "challenge" || entry.Action == "log"
}

func securityEvents(entries []storage.LogEntry) []storage.LogEntry {
	out := make([]storage.LogEntry, 0, len(entries))
	for _, entry := range entries {
		if isSecurityEvent(entry) {
			out = append(out, entry)
		}
	}
	return out
}

func heuristicAssistantReply(question string, events []storage.LogEntry) *AssistantReply {
	if len(events) == 0 {
		return &AssistantReply{Answer: "当前没有可分析的真实攻击或拦截事件。请先确认访问日志已写入，并让 WAF 产生 block/challenge/log 事件。"}
	}
	topIP := topValue(events, func(entry storage.LogEntry) string { return entry.ClientIP })
	topCategory := topValue(events, func(entry storage.LogEntry) string { return strings.ToUpper(emptyAs(entry.Category, entry.Action)) })
	latest := events[0]
	answer := fmt.Sprintf("基于最近 %d 条真实安全事件，主要来源 IP 是 %s，主要类型是 %s。最新事件 %s 对 %s 执行了 %s，建议先查看同源 IP 的相邻请求、确认规则命中证据，再决定拉黑、挑战或调低误报规则。", len(events), emptyAsUnknown(topIP), emptyAsUnknown(topCategory), emptyAsUnknown(latest.ID), emptyAsUnknown(latest.URI), emptyAs(latest.Action, "log"))
	if strings.Contains(strings.ToLower(question), "拦截") || strings.Contains(strings.ToLower(question), "block") {
		answer += " 当前回答只基于已记录的真实拦截/挑战/检测日志，不包含示例数据。"
	}
	return &AssistantReply{Answer: answer}
}

func topValue(entries []storage.LogEntry, value func(storage.LogEntry) string) string {
	counts := map[string]int{}
	var top string
	for _, entry := range entries {
		key := strings.TrimSpace(value(entry))
		if key == "" {
			continue
		}
		counts[key]++
		if top == "" || counts[key] > counts[top] {
			top = key
		}
	}
	return top
}

func compactEvents(entries []storage.LogEntry, limit int) []map[string]any {
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	out := make([]map[string]any, 0, limit)
	for _, entry := range entries[:limit] {
		out = append(out, map[string]any{
			"id":        entry.ID,
			"timestamp": entry.Timestamp,
			"trace_id":  entry.TraceID,
			"site_id":   entry.SiteID,
			"client_ip": entry.ClientIP,
			"method":    entry.Method,
			"uri":       entry.URI,
			"status":    entry.StatusCode,
			"action":    entry.Action,
			"category":  entry.Category,
			"severity":  entry.Severity,
			"message":   entry.Message,
			"payload":   entry.Payload,
			"country":   entry.Country,
		})
	}
	return out
}

func emptyAsUnknown(value string) string {
	return emptyAs(value, "unknown")
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
