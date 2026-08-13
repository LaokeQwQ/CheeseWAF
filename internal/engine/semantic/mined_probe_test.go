package semantic_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/securitytest"
)

// TestMinedProseFPProbe measures the false-positive rate against security prose
// mined from an external instruction-tuning corpus. These samples discuss
// attacks in natural language (CVE writeups, advisories, tutorials) and mention
// tokens like "select", "shell", "passwd" without carrying an executable
// primitive — exactly the surface where a keyword-driven WAF misfires.
//
// It is a REPORT, not a gate: set MINED_FP_GATE=1 to make it fail on any FP.
// Without that, it prints the rate and the offending samples so FP sources can
// be triaged one by one.
func TestMinedProseFPProbe(t *testing.T) {
	const path = "testdata/mined_secprose_probe.jsonl"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("probe corpus absent (%v) — mined corpus is opt-in", err)
		return
	}
	cases, err := securitytest.LoadJSONL(f)
	f.Close()
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if len(cases) == 0 {
		t.Skip("probe corpus empty")
		return
	}

	a := semantic.NewAnalyzer("block", 2)
	type fpRec struct {
		Name     string  `json:"name"`
		Category string  `json:"category"`
		Conf     float64 `json:"confidence"`
		Severity string  `json:"severity"`
		Payload  string  `json:"payload"`
		Message  string  `json:"message"`
	}
	var fps []fpRec
	byCategory := map[string]int{}
	total, skipped := 0, 0

	for _, tc := range cases {
		if tc.Label != "benign" {
			continue
		}
		method := tc.Method
		if method == "" {
			method = http.MethodPost
		}
		req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
		if err != nil || req == nil {
			skipped++
			continue
		}
		if tc.ContentType != "" {
			req.Header.Set("Content-Type", tc.ContentType)
		}
		reqCtx, err := engine.NewRequestContext(req, "default")
		if err != nil {
			skipped++
			continue
		}
		total++
		res, err := a.Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatalf("detect %s: %v", tc.Name, err)
		}
		if res != nil && res.Detected {
			payload := res.Payload
			if len(payload) > 160 {
				payload = payload[:160]
			}
			msg := res.Message
			if len(msg) > 200 {
				msg = msg[:200]
			}
			fps = append(fps, fpRec{
				Name:     tc.Name,
				Category: res.Category,
				Conf:     res.Confidence,
				Severity: res.Severity.String(),
				Payload:  payload,
				Message:  msg,
			})
			byCategory[res.Category]++
		}
	}

	rate := 0.0
	if total > 0 {
		rate = float64(len(fps)) / float64(total) * 100
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool {
		if byCategory[cats[i]] != byCategory[cats[j]] {
			return byCategory[cats[i]] > byCategory[cats[j]]
		}
		return cats[i] < cats[j]
	})
	catLines := make([]string, 0, len(cats))
	for _, c := range cats {
		catLines = append(catLines, fmt.Sprintf("%s=%d", c, byCategory[c]))
	}

	fmt.Println("===MINED_FP_PROBE===")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"probe_total":     total,
		"probe_skipped":   skipped,
		"fp_count":        len(fps),
		"fp_rate_percent": rate,
		"fp_by_category":  strings.Join(catLines, " "),
	})
	// Cap the detail dump so a bad regression cannot flood the log.
	limit := len(fps)
	if limit > 25 {
		limit = 25
	}
	for _, rec := range fps[:limit] {
		line, _ := json.Marshal(rec)
		fmt.Printf("FP %s\n", line)
	}
	if len(fps) > limit {
		fmt.Printf("... %d more FP suppressed\n", len(fps)-limit)
	}

	if os.Getenv("MINED_FP_GATE") == "1" && len(fps) != 0 {
		t.Fatalf("mined FP gate failed: %d / %d (%.4f%%)", len(fps), total, rate)
	}
}
