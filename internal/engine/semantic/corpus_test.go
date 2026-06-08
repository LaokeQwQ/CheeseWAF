package semantic

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type curatedCorpusCase struct {
	Name         string            `json:"name"`
	SourceFamily string            `json:"source_family"`
	Label        string            `json:"label"`
	Category     string            `json:"category"`
	Method       string            `json:"method"`
	Target       string            `json:"target"`
	ContentType  string            `json:"content_type"`
	Body         string            `json:"body"`
	Header       map[string]string `json:"header"`
	Rationale    string            `json:"rationale"`
}

func TestAnalyzerCuratedExternalCorpus(t *testing.T) {
	file, err := os.Open("testdata/curated_external_shapes.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		var tc curatedCorpusCase
		if err := json.Unmarshal(scanner.Bytes(), &tc); err != nil {
			t.Fatalf("line %d: %v", lineNo, err)
		}
		t.Run(tc.Name, func(t *testing.T) {
			req := readinessRequest(t, tc.Method, tc.Target, tc.ContentType, tc.Body)
			for key, value := range tc.Header {
				req.Header.Set(key, value)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.Label {
			case "attack":
				if result == nil || !result.Detected || result.Category != tc.Category {
					t.Fatalf("expected %s detection from %s sample, got %+v", tc.Category, tc.SourceFamily, result)
				}
			case "benign":
				if result != nil {
					t.Fatalf("expected benign %s sample to pass, got %+v", tc.SourceFamily, result)
				}
			default:
				t.Fatalf("unsupported label %q", tc.Label)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
