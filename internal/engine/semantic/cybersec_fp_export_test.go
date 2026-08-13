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

// TestCybersecBenignCorpus_ExportAllFPs exports ALL FP samples to tmp/cybersec_all_fps.jsonl
// for manual analysis. This is a one-time export test.
func TestCybersecBenignCorpus_ExportAllFPs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large corpus test in -short mode")
	}

	const path = "testdata/cybersec_benign_clean.jsonl"
	records, err := loadCybersecCorpus(path)
	if err != nil {
		t.Skipf("cybersec benign corpus absent (%v)", err)
		return
	}
	if len(records) == 0 {
		t.Skip("benign corpus empty")
		return
	}

	a := semantic.NewAnalyzer("block", 2)
	type fpRec struct {
		Index    int     `json:"index"`
		Category string  `json:"category"`
		Conf     float64 `json:"confidence"`
		Severity string  `json:"severity"`
		Payload  string  `json:"payload"`
		Message  string  `json:"message"`
	}
	var fps []fpRec
	byCategory := map[string]int{}
	total, skipped := 0, 0

	for idx, rec := range records {
		if rec.Label != "benign" {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, "http://test.example.com/api", strings.NewReader(rec.Payload))
		if err != nil || req == nil {
			skipped++
			continue
		}
		req.Header.Set("Content-Type", "text/plain")
		reqCtx, err := engine.NewRequestContext(req, "default")
		if err != nil {
			skipped++
			continue
		}
		total++
		res, err := a.Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatalf("detect record %d: %v", idx, err)
		}
		if res != nil && res.Detected {
			payload := res.Payload
			if len(payload) > 500 {
				payload = payload[:500]
			}
			msg := res.Message
			if len(msg) > 200 {
				msg = msg[:200]
			}
			fps = append(fps, fpRec{
				Index:    idx,
				Category: res.Category,
				Conf:     res.Confidence,
				Severity: res.Severity.String(),
				Payload:  payload,
				Message:  msg,
			})
			byCategory[res.Category]++
		}
	}

	// Export to tmp/cybersec_all_fps.jsonl
	outPath := "tmp/cybersec_all_fps.jsonl"
	os.MkdirAll("tmp", 0755)
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, fp := range fps {
		if err := enc.Encode(fp); err != nil {
			t.Fatalf("encode fp: %v", err)
		}
	}

	rate := 0.0
	if total > 0 {
		rate = float64(len(fps)) / float64(total) * 100
	}

	fmt.Printf("===EXPORT_COMPLETE===\n")
	fmt.Printf("Total FPs: %d / %d (%.2f%%)\n", len(fps), total, rate)
	fmt.Printf("By category:\n")
	for cat, count := range byCategory {
		fmt.Printf("  %s: %d\n", cat, count)
	}
	fmt.Printf("Output: %s\n", outPath)

	t.Logf("Exported %d FPs to %s", len(fps), outPath)
}
