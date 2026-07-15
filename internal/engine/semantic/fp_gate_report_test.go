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
	"github.com/LaokeQwQ/CheeseWAF/internal/securitytest"
)

func TestFPGateReport(t *testing.T) {
	semantic.ProcessMetrics().ResetForTest()
	semantic.ResetProcessCacheForTest()
	var benignTotal, benignFP, attackTotal, attackMiss, attackHit int
	a := semantic.NewAnalyzer("block")
	files := []string{
		"testdata/curated_external_shapes.jsonl",
		"testdata/benign_production_shapes.jsonl",
		"testdata/handcrafted_attack_neighbors.jsonl",
	}
	var cases []securitytest.Case
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		loaded, err := securitytest.LoadJSONL(f)
		f.Close()
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		cases = append(cases, loaded...)
	}
	for _, tc := range cases {
		method := tc.Method
		if method == "" {
			method = http.MethodGet
		}
		req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
		if err != nil {
			continue
		}
		if tc.ContentType != "" {
			req.Header.Set("Content-Type", tc.ContentType)
		}
		for k, v := range tc.Header {
			req.Header.Set(k, v)
		}
		reqCtx, err := engine.NewRequestContext(req, "default")
		if err != nil {
			continue
		}
		res, err := a.Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		detected := res != nil && res.Detected
		switch tc.Label {
		case "benign":
			benignTotal++
			if detected {
				benignFP++
				t.Errorf("FP: %s family=%s got=%+v", tc.Name, tc.SourceFamily, res)
			}
		case "attack":
			attackTotal++
			if detected {
				attackHit++
			} else {
				attackMiss++
				t.Errorf("MISS: %s family=%s want=%s", tc.Name, tc.SourceFamily, tc.Category)
			}
		}
	}
	fpRate := 0.0
	if benignTotal > 0 {
		fpRate = float64(benignFP) / float64(benignTotal) * 100
	}
	detectRate := 0.0
	if attackTotal > 0 {
		detectRate = float64(attackHit) / float64(attackTotal) * 100
	}
	summary := map[string]any{
		"benign_total":        benignTotal,
		"benign_fp":           benignFP,
		"benign_pass":         benignTotal - benignFP,
		"fp_rate_percent":     fpRate,
		"fp_rate_target_pct":  0.00001,
		"fp_gate_pass":        benignFP == 0,
		"attack_total":        attackTotal,
		"attack_hit":          attackHit,
		"attack_miss":         attackMiss,
		"detect_rate_percent": detectRate,
		"metrics":             semantic.ProcessMetrics().Snapshot(),
	}
	fmt.Println("===FP_GATE_SUMMARY===")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(summary)
	if benignFP != 0 {
		t.Fatalf("FP gate failed: %d FP / %d benign (%.8f%%)", benignFP, benignTotal, fpRate)
	}
	if attackMiss != 0 {
		t.Fatalf("attack miss: %d / %d", attackMiss, attackTotal)
	}
}
