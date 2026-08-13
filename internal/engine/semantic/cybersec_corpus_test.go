package semantic_test

import (
	"bufio"
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
)

// cybersecRecord is the schema from clean_cybersec_dataset.py output
type cybersecRecord struct {
	Payload string `json:"payload"`
	Label   string `json:"label"`
	Source  string `json:"source"`
	Note    string `json:"note"`
}

func loadCybersecCorpus(path string) ([]cybersecRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []cybersecRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // support large lines

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec cybersecRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// TestCybersecBenignCorpus measures FP rate on cleaned benign security prose
// from the Cybersecurity-Dataset (54,983 records, PII-redacted).
//
// These samples discuss attacks in natural language (CVE descriptions, wooyun
// reports, security papers, QA pairs) without carrying executable primitives.
// This is the WAF FP surface: keyword-rich text that must NOT trigger.
//
// Skip in -short mode (large corpus, ~30s runtime).
func TestCybersecBenignCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large corpus test in -short mode")
	}

	const path = "testdata/cybersec_benign_clean.jsonl"
	records, err := loadCybersecCorpus(path)
	if err != nil {
		t.Skipf("cybersec benign corpus absent (%v) — run tmp/clean_cybersec_dataset.py", err)
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
		// Wrap payload in POST body
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
			if len(payload) > 160 {
				payload = payload[:160]
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

	fmt.Println("===CYBERSEC_BENIGN_CORPUS===")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"corpus_total":    total,
		"corpus_skipped":  skipped,
		"fp_count":        len(fps),
		"fp_rate_percent": rate,
		"fp_by_category":  strings.Join(catLines, " "),
	})
	// Cap detail dump
	limit := len(fps)
	if limit > 200 {
		limit = 200
	}
	for _, rec := range fps[:limit] {
		line, _ := json.Marshal(rec)
		fmt.Printf("FP %s\n", line)
	}
	if len(fps) > limit {
		fmt.Printf("... %d more FP suppressed\n", len(fps)-limit)
	}

	// REPORT only, not a gate
	t.Logf("Cybersec benign corpus: %d / %d FP (%.2f%%)", len(fps), total, rate)
}

// TestCybersecAttackCorpus measures recall on cleaned attack payloads
// from the Cybersecurity-Dataset (6,142 payloads after marker validation).
//
// These are illustrative payloads mined from security text (not wire traffic).
// Labels: sqli, xss, rce, path, ssti, xxe, webshell.
//
// Skip in -short mode (large corpus, ~15s runtime).
func TestCybersecAttackCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large corpus test in -short mode")
	}

	const path = "testdata/cybersec_attack_clean.jsonl"
	records, err := loadCybersecCorpus(path)
	if err != nil {
		t.Skipf("cybersec attack corpus absent (%v) — run tmp/clean_cybersec_dataset.py", err)
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
		Payload string `json:"payload"`
	}
	var misses []missRec
	byLabel := map[string]struct{ total, detected int }{}
	total, skipped := 0, 0

	for idx, rec := range records {
		if rec.Label == "benign" {
			continue
		}
		// Wrap payload in POST body
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
		label := rec.Label
		if label == "" {
			label = "attack"
		}
		st := byLabel[label]
		st.total++
		byLabel[label] = st

		res, err := a.Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatalf("detect record %d: %v", idx, err)
		}
		if res != nil && res.Detected {
			st.detected++
			byLabel[label] = st
		} else {
			// Miss
			payload := rec.Payload
			if len(payload) > 160 {
				payload = payload[:160]
			}
			misses = append(misses, missRec{
				Index:   idx,
				Label:   label,
				Payload: payload,
			})
		}
	}

	detected := total - len(misses)
	recall := 0.0
	if total > 0 {
		recall = float64(detected) / float64(total) * 100
	}

	// Per-label recall
	labels := make([]string, 0, len(byLabel))
	for lb := range byLabel {
		labels = append(labels, lb)
	}
	sort.Strings(labels)
	labelRecalls := make([]string, 0, len(labels))
	for _, lb := range labels {
		st := byLabel[lb]
		r := 0.0
		if st.total > 0 {
			r = float64(st.detected) / float64(st.total) * 100
		}
		labelRecalls = append(labelRecalls, fmt.Sprintf("%s=%.1f%%", lb, r))
	}

	fmt.Println("===CYBERSEC_ATTACK_CORPUS===")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"corpus_total":    total,
		"corpus_skipped":  skipped,
		"detected":        detected,
		"missed":          len(misses),
		"recall_percent":  recall,
		"recall_by_label": strings.Join(labelRecalls, " "),
	})
	// Cap detail dump
	limit := len(misses)
	if limit > 30 {
		limit = 30
	}
	for _, rec := range misses[:limit] {
		line, _ := json.Marshal(rec)
		fmt.Printf("MISS %s\n", line)
	}
	if len(misses) > limit {
		fmt.Printf("... %d more MISS suppressed\n", len(misses)-limit)
	}

	// REPORT only, not a gate
	t.Logf("Cybersec attack corpus: %d / %d detected (%.2f%% recall)", detected, total, recall)
}
