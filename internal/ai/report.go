package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type ReportInput struct {
	Period    string             `json:"period"`
	Entries   []storage.LogEntry `json:"entries"`
	Anomalies []TrafficAnomaly   `json:"anomalies"`
}

func GenerateReport(ctx context.Context, client *Client, input ReportInput) (string, error) {
	brief := reportBrief(input)
	if client == nil {
		return brief, nil
	}
	narrative, err := client.Complete(ctx, []Message{
		{Role: "system", Content: "You write concise WAF security reports with direct operational recommendations."},
		{Role: "user", Content: "Turn this summary into a short security report:\n\n" + brief},
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(narrative), nil
}

func reportBrief(input ReportInput) string {
	if input.Period == "" {
		input.Period = "daily"
	}
	byCategory := map[string]int{}
	byIP := map[string]int{}
	blocked := 0
	for _, entry := range input.Entries {
		if entry.Action == "block" {
			blocked++
		}
		if entry.Category != "" {
			byCategory[entry.Category]++
		}
		if entry.ClientIP != "" {
			byIP[entry.ClientIP]++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CheeseWAF %s security report\n\n", input.Period)
	fmt.Fprintf(&b, "Total events: %d\n", len(input.Entries))
	fmt.Fprintf(&b, "Blocked events: %d\n\n", blocked)
	writeTop(&b, "Top categories", byCategory)
	writeTop(&b, "Top source IPs", byIP)
	if len(input.Anomalies) > 0 {
		b.WriteString("Anomalies:\n")
		for _, anomaly := range input.Anomalies {
			fmt.Fprintf(&b, "- [%s] %s\n", anomaly.Severity, anomaly.Message)
		}
	}
	return strings.TrimSpace(b.String())
}

func writeTop(b *strings.Builder, title string, values map[string]int) {
	b.WriteString(title + ":\n")
	if len(values) == 0 {
		b.WriteString("- none\n\n")
		return
	}
	type item struct {
		key   string
		count int
	}
	items := make([]item, 0, len(values))
	for key, count := range values {
		items = append(items, item{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].count > items[j].count })
	for idx, item := range items {
		if idx >= 5 {
			break
		}
		fmt.Fprintf(b, "- %s: %d\n", item.key, item.count)
	}
	b.WriteString("\n")
}
