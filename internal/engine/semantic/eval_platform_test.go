package semantic_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/securitytest"
)

// TestEvaluationPlatform provides a quantitative FPR/TPR measurement framework
// for the semantic engine. It processes multiple data sources (curated corpus,
// mined probe, optional external dataset) and outputs JSON metrics including:
// - FPR (false positive rate): benign samples misclassified as attack
// - TPR (true positive rate / recall): attack samples correctly detected
// - Precision: true attacks / all flagged as attack
// - F1 score: harmonic mean of precision and recall
// - Per-category breakdown
// - Performance metrics (latency p50/p95/p99)
// - Failed sample details for debugging
//
// In -short mode (CI) the large external dataset and the per-paranoia-level
// sweep are skipped, but the curated corpus and mined probe still run so that
// FPR_GATE / TPR_GATE remain real quality gates. Do NOT add a top-level
// t.Skip here: it silently turns the CI gate into a no-op.
func TestEvaluationPlatform(t *testing.T) {
	semantic.ProcessMetrics().ResetForTest()
	semantic.ResetProcessCacheForTest()

	analyzer := semantic.NewAnalyzer("block", 2)

	// Data sources configuration
	dataSources := []struct {
		name       string
		benignPath string
		attackPath string
		required   bool
		skipShort  bool
	}{
		{name: "curated_corpus", benignPath: "testdata/curated_external_shapes.jsonl", required: true, skipShort: false},
		{name: "mined_probe", benignPath: "testdata/mined_secprose_probe.jsonl", required: false, skipShort: false},
		{name: "external_dataset", benignPath: "testdata/cybersec_benign_clean.jsonl", attackPath: "testdata/cybersec_attack_clean.jsonl", required: false, skipShort: true},
	}

	report := &EvaluationReport{
		Timestamp:       time.Now().Format(time.RFC3339),
		Sources:         make(map[string]*SourceMetrics),
		ByCategory:      make(map[string]*CategoryMetrics),
		ByParanoiaLevel: make(map[string]*ParanoiaMetrics),
		FailedCases:     make([]FailedCase, 0),
	}

	for _, ds := range dataSources {
		if testing.Short() && ds.skipShort {
			t.Logf("Skipping %s in -short mode", ds.name)
			continue
		}

		t.Logf("Processing data source: %s", ds.name)
		if ds.attackPath != "" {
			// Process separate benign and attack files
			processDataSourceSplit(t, analyzer, ds.name, ds.benignPath, ds.attackPath, ds.required, report)
		} else {
			// Process single file with mixed labels
			processDataSource(t, analyzer, ds.name, ds.benignPath, ds.required, report)
		}
	}

	// Compute aggregate metrics
	computeAggregateMetrics(report)

	// Compute by-paranoia-level metrics. This re-scans every source once per
	// level (5x work, ~24 min on the full corpus) so it is skipped in -short
	// mode to stay inside the CI timeout.
	if testing.Short() {
		t.Log("Skipping by-paranoia-level sweep in -short mode")
	} else {
		computeByParanoiaLevel(t, dataSources, report)
	}

	// Add performance metrics from semantic engine
	report.Performance = &PerformanceMetrics{
		ProcessMetrics: semantic.ProcessMetrics().Snapshot(),
	}

	// Output JSON report
	outputReport(t, report)

	// Validation gates (optional - controlled by env vars)
	if os.Getenv("FPR_GATE") != "" {
		maxFPR := 0.0
		if _, err := fmt.Sscanf(os.Getenv("FPR_GATE"), "%f", &maxFPR); err == nil {
			if report.Overall.FPR > maxFPR {
				t.Fatalf("FPR gate failed: %.4f%% > %.4f%%", report.Overall.FPR, maxFPR)
			}
		}
	}

	if os.Getenv("TPR_GATE") != "" {
		minTPR := 0.0
		if _, err := fmt.Sscanf(os.Getenv("TPR_GATE"), "%f", &minTPR); err == nil {
			if report.Overall.TPR < minTPR {
				t.Fatalf("TPR gate failed: %.4f%% < %.4f%%", report.Overall.TPR, minTPR)
			}
		}
	}
}

type EvaluationReport struct {
	Timestamp       string                      `json:"timestamp"`
	Sources         map[string]*SourceMetrics   `json:"sources"`
	ByCategory      map[string]*CategoryMetrics `json:"by_category"`
	Overall         Metrics                     `json:"overall"`
	ByParanoiaLevel map[string]*ParanoiaMetrics `json:"by_paranoia_level"`
	Performance     *PerformanceMetrics         `json:"performance,omitempty"`
	FailedCases     []FailedCase                `json:"failed_cases"`
}

type ParanoiaMetrics struct {
	BenignTotal int     `json:"benign_total"`
	BenignFP    int     `json:"benign_fp"`
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	FPR         float64 `json:"fpr"`
	TPR         float64 `json:"tpr"`
}

type SourceMetrics struct {
	BenignTotal int     `json:"benign_total"`
	BenignFP    int     `json:"benign_fp"`
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	Metrics     Metrics `json:"metrics"`
}

type CategoryMetrics struct {
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	TPR         float64 `json:"tpr_percent"`
}

type Metrics struct {
	FPR       float64 `json:"fpr_percent"`
	TPR       float64 `json:"tpr_percent"`
	Precision float64 `json:"precision_percent"`
	F1Score   float64 `json:"f1_score"`
}

type PerformanceMetrics struct {
	ProcessMetrics semantic.Snapshot `json:"process_metrics"`
}

type FailedCase struct {
	Source   string `json:"source"`
	Type     string `json:"type"` // "FP" or "FN" (false negative)
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Expected string `json:"expected"`
	Got      string `json:"got,omitempty"`
	Payload  string `json:"payload,omitempty"`
}

func processDataSource(t *testing.T, analyzer *semantic.Analyzer, sourceName, path string, required bool, report *EvaluationReport) {
	f, err := os.Open(path)
	if err != nil {
		if required {
			t.Fatalf("Failed to open required data source %s: %v", sourceName, err)
		}
		t.Logf("Skipping optional data source %s: %v", sourceName, err)
		return
	}
	defer f.Close()

	cases, err := securitytest.LoadJSONL(f)
	if err != nil {
		t.Fatalf("Failed to load %s: %v", sourceName, err)
	}

	if len(cases) == 0 {
		t.Logf("Data source %s is empty", sourceName)
		return
	}

	srcMetrics := &SourceMetrics{}
	report.Sources[sourceName] = srcMetrics

	for _, tc := range cases {
		if !caseInShard(tc) {
			continue
		}
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

		res, err := analyzer.Detect(context.Background(), reqCtx)
		if err != nil {
			t.Errorf("Detection error on %s: %v", tc.Name, err)
			continue
		}

		detected := res != nil && res.Detected

		switch tc.Label {
		case "benign":
			srcMetrics.BenignTotal++
			if detected {
				srcMetrics.BenignFP++
				// Record FP for debugging (limit to avoid excessive output)
				if len(report.FailedCases) < 100 {
					payload := tc.Body
					if len(payload) > 200 {
						payload = payload[:200] + "..."
					}
					report.FailedCases = append(report.FailedCases, FailedCase{
						Source:   sourceName,
						Type:     "FP",
						Name:     tc.Name,
						Category: res.Category,
						Expected: "benign",
						Got:      fmt.Sprintf("%s (conf=%.2f)", res.Category, res.Confidence),
						Payload:  payload,
					})
				}
			}

		case "attack":
			srcMetrics.AttackTotal++
			if detected {
				srcMetrics.AttackHit++
				// Update category-specific metrics
				if report.ByCategory[tc.Category] == nil {
					report.ByCategory[tc.Category] = &CategoryMetrics{}
				}
				report.ByCategory[tc.Category].AttackTotal++
				report.ByCategory[tc.Category].AttackHit++
			} else {
				// Record false negative (miss)
				if len(report.FailedCases) < 100 {
					payload := tc.Body
					if len(payload) > 200 {
						payload = payload[:200] + "..."
					}
					report.FailedCases = append(report.FailedCases, FailedCase{
						Source:   sourceName,
						Type:     "FN",
						Name:     tc.Name,
						Category: tc.Category,
						Expected: tc.Category,
						Got:      "not_detected",
						Payload:  payload,
					})
				}
				// Still count total for category
				if report.ByCategory[tc.Category] == nil {
					report.ByCategory[tc.Category] = &CategoryMetrics{}
				}
				report.ByCategory[tc.Category].AttackTotal++
			}
		}
	}

	// Compute metrics for this source
	srcMetrics.Metrics = computeMetrics(
		srcMetrics.BenignTotal,
		srcMetrics.BenignFP,
		srcMetrics.AttackTotal,
		srcMetrics.AttackHit,
	)

	t.Logf("Processed %s: %d benign (%d FP), %d attack (%d hit)",
		sourceName,
		srcMetrics.BenignTotal,
		srcMetrics.BenignFP,
		srcMetrics.AttackTotal,
		srcMetrics.AttackHit,
	)
}

func computeMetrics(benignTotal, benignFP, attackTotal, attackHit int) Metrics {
	m := Metrics{}

	// FPR: false positives / total benign
	if benignTotal > 0 {
		m.FPR = float64(benignFP) / float64(benignTotal) * 100
	}

	// TPR (recall): true positives / total attack
	if attackTotal > 0 {
		m.TPR = float64(attackHit) / float64(attackTotal) * 100
	}

	// Precision: true positives / (true positives + false positives)
	totalPositive := attackHit + benignFP
	if totalPositive > 0 {
		m.Precision = float64(attackHit) / float64(totalPositive) * 100
	}

	// F1: harmonic mean of precision and recall
	if m.Precision > 0 && m.TPR > 0 {
		m.F1Score = 2 * (m.Precision * m.TPR) / (m.Precision + m.TPR)
	}

	return m
}

func computeAggregateMetrics(report *EvaluationReport) {
	var totalBenign, totalBenignFP, totalAttack, totalAttackHit int

	for _, src := range report.Sources {
		totalBenign += src.BenignTotal
		totalBenignFP += src.BenignFP
		totalAttack += src.AttackTotal
		totalAttackHit += src.AttackHit
	}

	report.Overall = computeMetrics(totalBenign, totalBenignFP, totalAttack, totalAttackHit)

	// Compute per-category TPR
	for cat, metrics := range report.ByCategory {
		if metrics.AttackTotal > 0 {
			metrics.TPR = float64(metrics.AttackHit) / float64(metrics.AttackTotal) * 100
		}
		report.ByCategory[cat] = metrics
	}
}

func outputReport(t *testing.T, report *EvaluationReport) {
	fmt.Println("\n===EVALUATION_PLATFORM_REPORT===")

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		t.Errorf("Failed to encode report: %v", err)
	}

	// Human-readable summary
	fmt.Println("\n===SUMMARY===")
	fmt.Printf("Overall FPR: %.4f%% (%d FP / %d benign)\n",
		report.Overall.FPR,
		sumFP(report.Sources),
		sumBenign(report.Sources),
	)
	fmt.Printf("Overall TPR: %.4f%% (%d hit / %d attack)\n",
		report.Overall.TPR,
		sumAttackHit(report.Sources),
		sumAttack(report.Sources),
	)
	fmt.Printf("Precision: %.4f%%\n", report.Overall.Precision)
	fmt.Printf("F1 Score: %.4f\n", report.Overall.F1Score)

	// Category breakdown
	if len(report.ByCategory) > 0 {
		fmt.Println("\n===BY_CATEGORY===")
		cats := make([]string, 0, len(report.ByCategory))
		for cat := range report.ByCategory {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			m := report.ByCategory[cat]
			fmt.Printf("%s: %.2f%% (%d / %d)\n", cat, m.TPR, m.AttackHit, m.AttackTotal)
		}
	}

	// Paranoia level breakdown
	if len(report.ByParanoiaLevel) > 0 {
		fmt.Println("\n===BY_PARANOIA_LEVEL===")
		for level := 0; level <= 5; level++ {
			levelKey := fmt.Sprintf("%d", level)
			if m, ok := report.ByParanoiaLevel[levelKey]; ok {
				fmt.Printf("Level %d: FPR=%.2f%% (%d/%d), TPR=%.2f%% (%d/%d)\n",
					level, m.FPR, m.BenignFP, m.BenignTotal, m.TPR, m.AttackHit, m.AttackTotal)
			}
		}
	}

	// Failed cases summary
	if len(report.FailedCases) > 0 {
		fmt.Printf("\n===FAILED_CASES=== (showing up to 100)\n")
		fpCount := 0
		fnCount := 0
		for _, fc := range report.FailedCases {
			if fc.Type == "FP" {
				fpCount++
			} else {
				fnCount++
			}
		}
		fmt.Printf("False Positives: %d, False Negatives: %d\n", fpCount, fnCount)
	}

	// Optionally write to file
	if outPath := os.Getenv("EVAL_REPORT_PATH"); outPath != "" {
		outFile, err := os.Create(outPath)
		if err != nil {
			t.Logf("Failed to create report file %s: %v", outPath, err)
			return
		}
		defer outFile.Close()

		enc := json.NewEncoder(outFile)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			t.Logf("Failed to write report to %s: %v", outPath, err)
		} else {
			fmt.Printf("\nReport written to: %s\n", outPath)
		}
	}
}

func sumBenign(sources map[string]*SourceMetrics) int {
	total := 0
	for _, s := range sources {
		total += s.BenignTotal
	}
	return total
}

func sumFP(sources map[string]*SourceMetrics) int {
	total := 0
	for _, s := range sources {
		total += s.BenignFP
	}
	return total
}

func sumAttack(sources map[string]*SourceMetrics) int {
	total := 0
	for _, s := range sources {
		total += s.AttackTotal
	}
	return total
}

func sumAttackHit(sources map[string]*SourceMetrics) int {
	total := 0
	for _, s := range sources {
		total += s.AttackHit
	}
	return total
}

func processDataSourceSplit(t *testing.T, analyzer *semantic.Analyzer, sourceName, benignPath, attackPath string, required bool, report *EvaluationReport) {
	srcMetrics := &SourceMetrics{}
	report.Sources[sourceName] = srcMetrics

	// Process benign samples
	if benignPath != "" {
		f, err := os.Open(benignPath)
		if err != nil {
			if required {
				t.Fatalf("Failed to open required benign file %s: %v", benignPath, err)
			}
			t.Logf("Skipping optional benign file %s: %v", benignPath, err)
		} else {
			defer f.Close()
			cases, err := loadCybersecJSONL(f, "benign")
			if err != nil {
				t.Fatalf("Failed to load benign samples from %s: %v", benignPath, err)
			}

			for _, tc := range cases {
				if !caseInShard(tc) {
					continue
				}
				srcMetrics.BenignTotal++
				if detectSample(t, analyzer, &tc, report, sourceName, "benign") {
					srcMetrics.BenignFP++
				}
			}
		}
	}

	// Process attack samples
	if attackPath != "" {
		f, err := os.Open(attackPath)
		if err != nil {
			if required {
				t.Fatalf("Failed to open required attack file %s: %v", attackPath, err)
			}
			t.Logf("Skipping optional attack file %s: %v", attackPath, err)
		} else {
			defer f.Close()
			cases, err := loadCybersecJSONL(f, "attack")
			if err != nil {
				t.Fatalf("Failed to load attack samples from %s: %v", attackPath, err)
			}

			for _, tc := range cases {
				if !caseInShard(tc) {
					continue
				}
				srcMetrics.AttackTotal++
				if detectSample(t, analyzer, &tc, report, sourceName, "attack") {
					srcMetrics.AttackHit++
					// Update category-specific metrics
					if report.ByCategory[tc.Category] == nil {
						report.ByCategory[tc.Category] = &CategoryMetrics{}
					}
					report.ByCategory[tc.Category].AttackTotal++
					report.ByCategory[tc.Category].AttackHit++
				} else {
					// Still count total for category
					if report.ByCategory[tc.Category] == nil {
						report.ByCategory[tc.Category] = &CategoryMetrics{}
					}
					report.ByCategory[tc.Category].AttackTotal++
				}
			}
		}
	}

	// Compute metrics for this source
	srcMetrics.Metrics = computeMetrics(
		srcMetrics.BenignTotal,
		srcMetrics.BenignFP,
		srcMetrics.AttackTotal,
		srcMetrics.AttackHit,
	)

	t.Logf("Processed %s: %d benign (%d FP), %d attack (%d hit)",
		sourceName,
		srcMetrics.BenignTotal,
		srcMetrics.BenignFP,
		srcMetrics.AttackTotal,
		srcMetrics.AttackHit,
	)
}

// loadCybersecJSONL loads Cybersecurity-Dataset format (payload/label/source/note)
// and converts to securitytest.Case format
func loadCybersecJSONL(r io.Reader, expectedLabel string) ([]securitytest.Case, error) {
	type cybersecEntry struct {
		Payload string `json:"payload"`
		Label   string `json:"label"`
		Source  string `json:"source"`
		Note    string `json:"note"`
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var cases []securitytest.Case
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry cybersecEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		// Map label to category for attack samples
		category := ""
		if expectedLabel == "attack" {
			category = mapLabelToCategory(entry.Label)
		}

		tc := securitytest.Case{
			Name:         fmt.Sprintf("cybersec-%d", lineNo),
			SourceFamily: entry.Source,
			Label:        expectedLabel,
			Category:     category,
			Method:       "POST",
			Target:       "/api/test",
			ContentType:  "application/json",
			Body:         entry.Payload,
		}

		cases = append(cases, tc)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cases, nil
}

// mapLabelToCategory maps cybersec dataset labels to CheeseWAF categories
func mapLabelToCategory(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	switch label {
	case "sqli", "sql":
		return "sqli"
	case "xss":
		return "xss"
	case "rce", "command":
		return "rce"
	case "lfi", "path", "directory":
		return "lfi"
	case "ssrf":
		return "ssrf"
	case "nosqli", "nosql":
		return "nosqli"
	case "ssti":
		return "ssti"
	case "xxe":
		return "xxe"
	default:
		// Generic attack category for unmapped types
		return "generic"
	}
}

func detectSample(t *testing.T, analyzer *semantic.Analyzer, tc *securitytest.Case, report *EvaluationReport, sourceName, expectedLabel string) bool {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		return false
	}

	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	for k, v := range tc.Header {
		req.Header.Set(k, v)
	}

	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		return false
	}

	res, err := analyzer.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Errorf("Detection error on %s: %v", tc.Name, err)
		return false
	}

	detected := res != nil && res.Detected

	// Record failures
	if expectedLabel == "benign" && detected {
		if len(report.FailedCases) < 100 {
			payload := tc.Body
			if len(payload) > 200 {
				payload = payload[:200] + "..."
			}
			report.FailedCases = append(report.FailedCases, FailedCase{
				Source:   sourceName,
				Type:     "FP",
				Name:     tc.Name,
				Category: res.Category,
				Expected: "benign",
				Got:      fmt.Sprintf("%s (conf=%.2f)", res.Category, res.Confidence),
				Payload:  payload,
			})
		}
	} else if expectedLabel == "attack" && !detected {
		if len(report.FailedCases) < 100 {
			payload := tc.Body
			if len(payload) > 200 {
				payload = payload[:200] + "..."
			}
			report.FailedCases = append(report.FailedCases, FailedCase{
				Source:   sourceName,
				Type:     "FN",
				Name:     tc.Name,
				Category: tc.Category,
				Expected: tc.Category,
				Got:      "not_detected",
				Payload:  payload,
			})
		}
	}

	return detected
}

// computeByParanoiaLevel evaluates detection metrics across paranoia levels 0-4
func computeByParanoiaLevel(t *testing.T, dataSources []struct {
	name       string
	benignPath string
	attackPath string
	required   bool
	skipShort  bool
}, report *EvaluationReport) {

	t.Logf("\n===Computing by-paranoia-level metrics===")

	for level := 0; level <= 5; level++ {
		t.Logf("Evaluating paranoia level %d", level)

		// Create analyzer with specific paranoia level
		analyzer := semantic.NewAnalyzer("block", level)

		var totalBenign, totalBenignFP, totalAttack, totalAttackHit int

		for _, ds := range dataSources {
			if testing.Short() && ds.skipShort {
				continue
			}

			// Process benign samples
			if ds.benignPath != "" {
				f, err := os.Open(ds.benignPath)
				if err != nil {
					if ds.required {
						t.Fatalf("Failed to open required benign file %s: %v", ds.benignPath, err)
					}
					continue
				}

				var cases []securitytest.Case
				if ds.attackPath != "" {
					// Cybersec format
					cases, err = loadCybersecJSONL(f, "benign")
				} else {
					// Standard JSONL format
					cases, err = securitytest.LoadJSONL(f)
					if err == nil {
						// Filter to benign only
						benignCases := make([]securitytest.Case, 0)
						for _, tc := range cases {
							if !caseInShard(tc) {
								continue
							}
							if tc.Label == "benign" {
								benignCases = append(benignCases, tc)
							}
						}
						cases = benignCases
					}
				}
				f.Close()

				if err != nil {
					continue
				}

				for _, tc := range cases {
					if !caseInShard(tc) {
						continue
					}
					totalBenign++
					if detectSampleQuiet(analyzer, &tc) {
						totalBenignFP++
					}
				}
			}

			// Process attack samples
			if ds.attackPath != "" {
				f, err := os.Open(ds.attackPath)
				if err != nil {
					if ds.required {
						t.Fatalf("Failed to open required attack file %s: %v", ds.attackPath, err)
					}
					continue
				}

				cases, err := loadCybersecJSONL(f, "attack")
				f.Close()

				if err != nil {
					continue
				}

				for _, tc := range cases {
					if !caseInShard(tc) {
						continue
					}
					totalAttack++
					if detectSampleQuiet(analyzer, &tc) {
						totalAttackHit++
					}
				}
			} else {
				// Mixed format - process attack samples
				f, err := os.Open(ds.benignPath)
				if err != nil {
					continue
				}

				cases, err := securitytest.LoadJSONL(f)
				f.Close()

				if err != nil {
					continue
				}

				for _, tc := range cases {
					if !caseInShard(tc) {
						continue
					}
					if tc.Label == "attack" {
						totalAttack++
						if detectSampleQuiet(analyzer, &tc) {
							totalAttackHit++
						}
					}
				}
			}
		}

		// Compute FPR/TPR for this level
		fpr := 0.0
		if totalBenign > 0 {
			fpr = float64(totalBenignFP) / float64(totalBenign) * 100
		}

		tpr := 0.0
		if totalAttack > 0 {
			tpr = float64(totalAttackHit) / float64(totalAttack) * 100
		}

		levelKey := fmt.Sprintf("%d", level)
		report.ByParanoiaLevel[levelKey] = &ParanoiaMetrics{
			BenignTotal: totalBenign,
			BenignFP:    totalBenignFP,
			AttackTotal: totalAttack,
			AttackHit:   totalAttackHit,
			FPR:         fpr,
			TPR:         tpr,
		}

		t.Logf("Level %d: FPR=%.2f%% (%d/%d), TPR=%.2f%% (%d/%d)",
			level, fpr, totalBenignFP, totalBenign, tpr, totalAttackHit, totalAttack)
	}
}

// detectSampleQuiet runs detection without recording failures (for paranoia-level sweep)
func detectSampleQuiet(analyzer *semantic.Analyzer, tc *securitytest.Case) bool {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		return false
	}

	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	for k, v := range tc.Header {
		req.Header.Set(k, v)
	}

	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		return false
	}

	res, err := analyzer.Detect(context.Background(), reqCtx)
	if err != nil {
		return false
	}

	return res != nil && res.Detected
}

func evalShardTotal() int {
	v := strings.TrimSpace(os.Getenv("SEMANTIC_EVAL_SHARDS"))
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func evalShardIndex(shards int) int {
	v := strings.TrimSpace(os.Getenv("SEMANTIC_EVAL_SHARD_INDEX"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n >= shards {
		return 0
	}
	return n
}

func caseInShard(tc securitytest.Case) bool {
	shards := evalShardTotal()
	if shards <= 1 {
		return true
	}
	return securitytest.ShardIndexFor(tc.Name, shards) == evalShardIndex(shards)
}
