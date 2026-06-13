package ai

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestHeuristicAnalysisUsesTraceIDWhenLogIDMissing(t *testing.T) {
	analysis := HeuristicAnalysis(storage.LogEntry{
		TraceID:  "cw-trace-only",
		Action:   "block",
		Category: "sqli",
		ClientIP: "203.0.113.7",
		URI:      "/search?q=1",
	})
	if analysis.LogID != "cw-trace-only" {
		t.Fatalf("LogID = %q, want trace id fallback", analysis.LogID)
	}
}
