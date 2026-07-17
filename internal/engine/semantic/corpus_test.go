package semantic

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/securitytest"
)

func TestAnalyzerCuratedExternalCorpus(t *testing.T) {
	cases := loadAllCorpusCases(t)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.SourceFamily+"/"+tc.Name, func(t *testing.T) {
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
					if !categoryMatch {
						t.Fatalf("STRICT: expected %s detection from %s (%s), got category=%v", tc.Category, tc.Name, tc.SourceFamily, result)
					}
				} else if !detected {
					t.Fatalf("DETECT: expected ANY detection from %s (%s), got nil", tc.Name, tc.SourceFamily)
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

func loadAllCorpusCases(t *testing.T) []securitytest.Case {
	t.Helper()
	files := []string{
		"testdata/curated_external_shapes.jsonl",
		"testdata/benign_production_shapes.jsonl",
		"testdata/handcrafted_attack_neighbors.jsonl",
	}
	var all []securitytest.Case
	for _, name := range files {
		path := name
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join("testdata", filepath.Base(name))
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		cases, err := securitytest.LoadJSONL(file)
		file.Close()
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		all = append(all, cases...)
	}
	return all
}
