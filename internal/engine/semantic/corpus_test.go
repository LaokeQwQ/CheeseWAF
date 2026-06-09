package semantic

import (
	"context"
	"os"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/securitytest"
)

func TestAnalyzerCuratedExternalCorpus(t *testing.T) {
	file, err := os.Open("testdata/curated_external_shapes.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	cases, err := securitytest.LoadJSONL(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
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
}
