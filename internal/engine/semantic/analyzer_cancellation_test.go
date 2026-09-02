package semantic

import (
	"context"
	"fmt"
	"testing"
)

func TestAnalyzeAllCandidatesAlreadyCanceledPreservesInputs(t *testing.T) {
	a := NewAnalyzer("block", 5, "rce")
	for _, size := range []int{1, 3, parallelCandidateThreshold, maxCandidates} {
		t.Run(fmt.Sprintf("candidates-%d", size), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			candidates := make([]semanticCandidate, size)
			for i := range candidates {
				candidates[i] = semanticCandidate{
					input: InputPoint{Source: "query", Name: fmt.Sprintf("p%d", i)},
					text:  ";bash -c id",
				}
			}

			report, _, haveBest, incomplete := a.analyzeAllCandidates(ctx, candidates)
			if !incomplete {
				t.Fatal("already-canceled scan must be marked incomplete")
			}
			if haveBest {
				t.Fatal("already-canceled scan must not analyze a candidate")
			}
			if len(report.Hits) != 0 {
				t.Fatalf("already-canceled scan produced %d hits", len(report.Hits))
			}
			if len(report.Inputs) != size {
				t.Fatalf("report input count=%d, want %d", len(report.Inputs), size)
			}
			for i, input := range report.Inputs {
				if input.Source != candidates[i].input.Source || input.Name != candidates[i].input.Name {
					t.Fatalf("report input %d=%+v, want %+v", i, input, candidates[i].input)
				}
			}
		})
	}
}
