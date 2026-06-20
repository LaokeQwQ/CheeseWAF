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
			if req == nil || req.URL == nil {
				t.Skipf("skipping malformed corpus entry %q: target could not be parsed as valid HTTP request", tc.Name)
				return
			}
			for key, value := range tc.Header {
				req.Header.Set(key, value)
			}
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Skipf("skipping corpus entry %q: %v", tc.Name, err)
				return
			}
			result, err := NewAnalyzer("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.Label {
			case "attack":
				detected := result != nil && result.Detected
				categoryMatch := result != nil && result.Category == tc.Category
				if securitytest.StrictCategory(tc.SourceFamily) {
					// Handcrafted/curated: must detect AND match exact category
					if !categoryMatch {
						t.Fatalf("STRICT: expected %s detection from %s (%s), got category=%v", tc.Category, tc.Name, tc.SourceFamily, result)
					}
				} else {
					// Bulk external import: only require detection
					if !detected {
						t.Fatalf("DETECT: expected ANY detection from %s (%s), got nil", tc.Name, tc.SourceFamily)
					}
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
