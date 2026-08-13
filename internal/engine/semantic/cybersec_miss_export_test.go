package semantic_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
)

// TestCybersecAttackCorpus_ExportAllMisses exports every missed attack payload to
// tmp/cybersec_all_misses.jsonl so recall gaps can be clustered offline.
// Detection-gap triage tool, not a gate.
func TestCybersecAttackCorpus_ExportAllMisses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large corpus test in -short mode")
	}

	const path = "testdata/cybersec_attack_clean.jsonl"
	records, err := loadCybersecCorpus(path)
	if err != nil {
		t.Skipf("cybersec attack corpus absent (%v)", err)
		return
	}
	if len(records) == 0 {
		t.Skip("attack corpus empty")
		return
	}

	a := semantic.NewAnalyzer("block", 2)
	type missRec struct {
		Index   int    `json:"index"`
		Label   string `json:"label"`
		Length  int    `json:"length"`
		Payload string `json:"payload"`
	}
	var misses []missRec
	byLabel := map[string]struct{ total, missed int }{}
	total := 0

	for idx, rec := range records {
		if rec.Label == "benign" {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, "http://test.example.com/api", strings.NewReader(rec.Payload))
		if err != nil || req == nil {
			continue
		}
		req.Header.Set("Content-Type", "text/plain")
		reqCtx, err := engine.NewRequestContext(req, "default")
		if err != nil {
			continue
		}
		total++
		label := rec.Label
		if label == "" {
			label = "attack"
		}
		st := byLabel[label]
		st.total++

		res, err := a.Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatalf("detect record %d: %v", idx, err)
		}
		if res == nil || !res.Detected {
			st.missed++
			misses = append(misses, missRec{
				Index:   idx,
				Label:   label,
				Length:  len(rec.Payload),
				Payload: rec.Payload,
			})
		}
		byLabel[label] = st
	}

	outPath := "tmp/cybersec_all_misses.jsonl"
	_ = os.MkdirAll("tmp", 0o755)
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, m := range misses {
		if err := enc.Encode(m); err != nil {
			t.Fatalf("encode miss: %v", err)
		}
	}

	fmt.Println("===MISS_EXPORT_COMPLETE===")
	fmt.Printf("Total misses: %d / %d (%.2f%% recall)\n",
		len(misses), total, float64(total-len(misses))/float64(total)*100)
	fmt.Println("By label (missed/total):")
	for lb, st := range byLabel {
		fmt.Printf("  %s: %d/%d\n", lb, st.missed, st.total)
	}
	fmt.Printf("Output: %s\n", outPath)
}
