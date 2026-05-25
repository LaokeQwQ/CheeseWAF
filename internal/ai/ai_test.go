package ai

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestHeuristicAnalysisFlagsHighSignalCategory(t *testing.T) {
	analysis := HeuristicAnalysis(storage.LogEntry{
		ID:       "log-1",
		Method:   "GET",
		URI:      "/search?q=1",
		ClientIP: "203.0.113.10",
		Category: "sqli",
		Action:   "block",
	})
	if analysis.Risk != "high" || !strings.Contains(analysis.Summary, "sqli") {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
}

func TestDetectAnomaliesFindsRepeatedSource(t *testing.T) {
	now := time.Date(2026, 5, 25, 8, 0, 0, 0, time.UTC)
	var entries []storage.LogEntry
	for i := 0; i < 5; i++ {
		entries = append(entries, storage.LogEntry{Timestamp: now.Add(-time.Minute), ClientIP: "203.0.113.10", Action: "block"})
	}
	anomalies := DetectAnomalies(entries, time.Hour, now)
	if len(anomalies) != 1 || anomalies[0].Key != "203.0.113.10" {
		t.Fatalf("expected source anomaly, got %+v", anomalies)
	}
}

func TestRegistryListsToolsForLLM(t *testing.T) {
	registry := NewDefaultRegistry(&config.Config{})
	tools := registry.ListForLLM()
	if len(tools) != 1 {
		t.Fatalf("expected one default tool, got %d", len(tools))
	}
	fn := tools[0]["function"].(map[string]any)
	if fn["name"] != "system_summary" {
		t.Fatalf("unexpected tool definition: %+v", tools[0])
	}
}

func TestAssistantRequiresApprovalForSensitiveTool(t *testing.T) {
	registry := NewRegistry()
	registry.Register(fakeTool{sensitivity: Modify})
	assistant := NewAssistant(registry, NewApprovalStore())

	first, err := assistant.ExecuteTool(context.Background(), "fake_modify", nil, "")
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if first.Approval == nil || first.Result != nil {
		t.Fatalf("expected pending approval, got %+v", first)
	}
	approved, err := assistant.Approve(first.Approval.ID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	second, err := assistant.ExecuteTool(context.Background(), "fake_modify", nil, approved.ID)
	if err != nil {
		t.Fatalf("execute approved tool: %v", err)
	}
	if second.Result == nil || !second.Result.Success {
		t.Fatalf("expected successful result, got %+v", second)
	}
}

type fakeTool struct {
	sensitivity ToolSensitivity
}

func (f fakeTool) Name() string {
	return "fake_modify"
}

func (fakeTool) Description() string {
	return "fake modify tool"
}

func (f fakeTool) Sensitivity() ToolSensitivity {
	return f.sensitivity
}

func (fakeTool) Parameters() map[string]any {
	return map[string]any{"type": "object"}
}

func (fakeTool) Execute(context.Context, map[string]any) (*ToolResult, error) {
	return &ToolResult{Success: true, Output: "ok"}, nil
}
