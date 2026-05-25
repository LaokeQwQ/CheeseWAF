package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type AttackAnalysis struct {
	LogID              string   `json:"log_id"`
	Risk               string   `json:"risk"`
	Summary            string   `json:"summary"`
	RecommendedActions []string `json:"recommended_actions"`
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
	}
	return base, nil
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
		RecommendedActions: actions,
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

func emptyAsUnknown(value string) string {
	return emptyAs(value, "unknown")
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
