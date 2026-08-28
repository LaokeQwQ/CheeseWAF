package semantic

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
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
	ProcessMetrics().ResetForTest()
	ResetProcessCacheForTest()
	_ = os.Setenv("CHEESEWAF_SEMANTIC_DEBUG_METADATA", "1")
	defer func() { _ = os.Unsetenv("CHEESEWAF_SEMANTIC_DEBUG_METADATA") }()

	analyzer := NewAnalyzer("block", 2)

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
		ProcessMetrics: ProcessMetrics().Snapshot(),
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
	Overall         EvalMetrics                 `json:"overall"`
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
	BenignTotal int         `json:"benign_total"`
	BenignFP    int         `json:"benign_fp"`
	AttackTotal int         `json:"attack_total"`
	AttackHit   int         `json:"attack_hit"`
	EvalMetrics EvalMetrics `json:"metrics"`
}

type CategoryMetrics struct {
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	TPR         float64 `json:"tpr_percent"`
}

type EvalMetrics struct {
	FPR       float64 `json:"fpr_percent"`
	TPR       float64 `json:"tpr_percent"`
	Precision float64 `json:"precision_percent"`
	F1Score   float64 `json:"f1_score"`
}

type PerformanceMetrics struct {
	ProcessMetrics Snapshot `json:"process_metrics"`
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

func processDataSource(t *testing.T, analyzer *Analyzer, sourceName, path string, required bool, report *EvaluationReport) {
	f, err := openCorpusFile(path)
	if err != nil {
		if required {
			t.Fatalf("Failed to open required data source %s: %v", sourceName, err)
		}
		t.Logf("Skipping optional data source %s: %v", sourceName, err)
		return
	}
	defer f.Close()

	srcMetrics := &SourceMetrics{}
	report.Sources[sourceName] = srcMetrics

	err = securitytest.ForEachJSONL(f, evalShardTotal(), evalShardIndex(evalShardTotal()), func(tc securitytest.Case) error {
		processOneSourceCase(t, analyzer, tc, sourceName, report, srcMetrics)
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to load/stream %s: %v", sourceName, err)
	}

	// Compute metrics for this source
	srcMetrics.EvalMetrics = computeMetrics(
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

func processOneSourceCase(t *testing.T, analyzer *Analyzer, tc securitytest.Case, sourceName string, report *EvaluationReport, srcMetrics *SourceMetrics) {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		return
	}

	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	for k, v := range tc.Header {
		req.Header.Set(k, v)
	}

	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		return
	}

	res, err := analyzer.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Errorf("Detection error on %s: %v", tc.Name, err)
		return
	}

	detected := res != nil && res.Detected

	switch tc.Label {
	case "benign":
		srcMetrics.BenignTotal++
		if detected {
			srcMetrics.BenignFP++
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
			if report.ByCategory[tc.Category] == nil {
				report.ByCategory[tc.Category] = &CategoryMetrics{}
			}
			report.ByCategory[tc.Category].AttackTotal++
			report.ByCategory[tc.Category].AttackHit++
		} else {
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
			if report.ByCategory[tc.Category] == nil {
				report.ByCategory[tc.Category] = &CategoryMetrics{}
			}
			report.ByCategory[tc.Category].AttackTotal++
		}
	}
}

func computeMetrics(benignTotal, benignFP, attackTotal, attackHit int) EvalMetrics {
	m := EvalMetrics{}

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

func processDataSourceSplit(t *testing.T, analyzer *Analyzer, sourceName, benignPath, attackPath string, required bool, report *EvaluationReport) {
	srcMetrics := &SourceMetrics{}
	report.Sources[sourceName] = srcMetrics

	// Process benign samples
	if benignPath != "" {
		f, err := openCorpusFile(benignPath)
		if err != nil {
			if required {
				t.Fatalf("Failed to open required benign file %s: %v", benignPath, err)
			}
			t.Logf("Skipping optional benign file %s: %v", benignPath, err)
		} else {
			defer f.Close()
			stats, streamErr := forEachCybersecJSONL(f, "benign", evalShardTotal(), evalShardIndex(evalShardTotal()), func(tc securitytest.Case) error {
				srcMetrics.BenignTotal++
				if detectSample(t, analyzer, &tc, report, sourceName, "benign") {
					srcMetrics.BenignFP++
				}
				return nil
			})
			if streamErr != nil {
				t.Fatalf("Failed to stream benign samples from %s: %v", benignPath, streamErr)
			}
			if stats.SkippedOverlong > 0 {
				t.Logf("Skipped %d overlong benign record(s) from %s", stats.SkippedOverlong, benignPath)
			}
		}
	}

	// Process attack samples
	if attackPath != "" {
		f, err := openCorpusFile(attackPath)
		if err != nil {
			if required {
				t.Fatalf("Failed to open required attack file %s: %v", attackPath, err)
			}
			t.Logf("Skipping optional attack file %s: %v", attackPath, err)
		} else {
			defer f.Close()
			stats, streamErr := forEachCybersecJSONL(f, "attack", evalShardTotal(), evalShardIndex(evalShardTotal()), func(tc securitytest.Case) error {
				srcMetrics.AttackTotal++
				if detectSample(t, analyzer, &tc, report, sourceName, "attack") {
					srcMetrics.AttackHit++
					if report.ByCategory[tc.Category] == nil {
						report.ByCategory[tc.Category] = &CategoryMetrics{}
					}
					report.ByCategory[tc.Category].AttackTotal++
					report.ByCategory[tc.Category].AttackHit++
				} else {
					if report.ByCategory[tc.Category] == nil {
						report.ByCategory[tc.Category] = &CategoryMetrics{}
					}
					report.ByCategory[tc.Category].AttackTotal++
				}
				return nil
			})
			if streamErr != nil {
				t.Fatalf("Failed to stream attack samples from %s: %v", attackPath, streamErr)
			}
			if stats.SkippedOverlong > 0 {
				t.Logf("Skipped %d overlong attack record(s) from %s", stats.SkippedOverlong, attackPath)
			}
		}
	}

	// Compute metrics for this source
	srcMetrics.EvalMetrics = computeMetrics(
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

type cybersecEntry struct {
	Payload string `json:"payload"`
	Label   string `json:"label"`
	Source  string `json:"source"`
	Note    string `json:"note"`
}

func forEachCybersecJSONL(r io.Reader, expectedLabel string, shards, shard int, fn func(securitytest.Case) error) (securitytest.JSONLStats, error) {
	return securitytest.ForEachJSONLRaw(r, shards, shard, func(line []byte, lineNo int, selected bool) error {
		var entry cybersecEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if !selected {
			return nil
		}
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
		if fn == nil {
			return nil
		}
		return fn(tc)
	})
}

func TestForEachCybersecJSONLSkipsOverlongRecordAndKeepsFollowingCase(t *testing.T) {
	t.Setenv("CHEESEWAF_CORPUS_MAX_LINE_BYTES", "128")
	long := `{"payload":"` + strings.Repeat("x", 512) + `","label":"sqli","source":"oversized"}`
	valid := `{"payload":"1 UNION SELECT password FROM users--","label":"sqli","source":"unit"}`
	var got []securitytest.Case
	stats, err := forEachCybersecJSONL(strings.NewReader(long+"\n"+valid+"\n"), "attack", 1, 0, func(tc securitytest.Case) error {
		got = append(got, tc)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.SkippedOverlong != 1 || len(got) != 1 || got[0].SourceFamily != "unit" {
		t.Fatalf("stats=%+v cases=%+v, want one skipped record and one valid case", stats, got)
	}
}

func TestParanoiaSweepUsesRawLineShardMembership(t *testing.T) {
	const shards = 2
	var corpusLine []byte
	for i := 0; i < 100; i++ {
		tc := securitytest.Case{
			Name:   fmt.Sprintf("paranoia-raw-shard-%d", i),
			Label:  "benign",
			Method: http.MethodGet,
			Target: "/health",
		}
		line, err := json.Marshal(tc)
		if err != nil {
			t.Fatal(err)
		}
		if securitytest.ShardIndexForRaw(line, shards) == 0 && securitytest.ShardIndexFor(tc.Name, shards) != 0 {
			corpusLine = append(line, '\n')
			break
		}
	}
	if len(corpusLine) == 0 {
		t.Fatal("failed to construct deterministic raw/name shard mismatch")
	}
	path := filepath.Join(t.TempDir(), "raw-shard.jsonl")
	if err := os.WriteFile(path, corpusLine, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEMANTIC_EVAL_SHARDS", "2")
	t.Setenv("SEMANTIC_EVAL_SHARD_INDEX", "0")
	t.Setenv("CHEESEWAF_SEMANTIC_DEBUG_METADATA", "1")
	report := &EvaluationReport{ByParanoiaLevel: make(map[string]*ParanoiaMetrics)}
	dataSources := []struct {
		name       string
		benignPath string
		attackPath string
		required   bool
		skipShort  bool
	}{{name: "raw_shard", benignPath: path, required: true}}

	computeByParanoiaLevel(t, dataSources, report)
	for level := 0; level <= 5; level++ {
		metrics := report.ByParanoiaLevel[strconv.Itoa(level)]
		if metrics == nil || metrics.BenignTotal != 1 {
			t.Fatalf("level %d metrics=%+v, want one raw-line selected sample", level, metrics)
		}
	}
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

func detectSample(t *testing.T, analyzer *Analyzer, tc *securitytest.Case, report *EvaluationReport, sourceName, expectedLabel string) bool {
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

// computeByParanoiaLevel evaluates detection metrics across paranoia levels 0-5
// in a single detection pass: each sample is analyzed once (mode log) and the
// collected Hits are re-graded offline with blockableHit per level. This avoids
// the previous 6x re-Detect cost (one analyzer per level).
type evalLevelTotals struct {
	benignTotal int
	benignFP    int
	attackTotal int
	attackHit   int
}

func computeByParanoiaLevel(t *testing.T, dataSources []struct {
	name       string
	benignPath string
	attackPath string
	required   bool
	skipShort  bool
}, report *EvaluationReport) {
	t.Logf("\n===Computing by-paranoia-level metrics (single-pass + offline grading)===")
	var totals [6]evalLevelTotals
	shards := evalShardTotal()
	shard := evalShardIndex(shards)

	for _, ds := range dataSources {
		if testing.Short() && ds.skipShort {
			continue
		}
		if ds.attackPath != "" {
			processCybersecLevels(t, ds, "benign", ds.benignPath, shards, shard, &totals)
			processCybersecLevels(t, ds, "attack", ds.attackPath, shards, shard, &totals)
			continue
		}
		f, err := openCorpusFile(ds.benignPath)
		if err != nil {
			if ds.required {
				t.Fatalf("Failed to open required benign file %s: %v", ds.benignPath, err)
			}
			continue
		}
		stats, streamErr := securitytest.ForEachJSONLWithStats(f, shards, shard, func(tc securitytest.Case) error {
			accumulateParanoiaTotals(t, tc, tc.Label, &totals)
			return nil
		})
		closeErr := f.Close()
		if streamErr != nil {
			t.Fatalf("Failed to stream paranoia samples from %s: %v", ds.benignPath, streamErr)
		}
		if closeErr != nil {
			t.Fatalf("Failed to close paranoia source %s: %v", ds.benignPath, closeErr)
		}
		if stats.SkippedOverlong > 0 {
			t.Logf("Skipped %d overlong paranoia record(s) from %s", stats.SkippedOverlong, ds.benignPath)
		}
	}

	for level := 0; level <= 5; level++ {
		fpr := 0.0
		if totals[level].benignTotal > 0 {
			fpr = float64(totals[level].benignFP) / float64(totals[level].benignTotal) * 100
		}
		tpr := 0.0
		if totals[level].attackTotal > 0 {
			tpr = float64(totals[level].attackHit) / float64(totals[level].attackTotal) * 100
		}
		levelKey := fmt.Sprintf("%d", level)
		report.ByParanoiaLevel[levelKey] = &ParanoiaMetrics{
			BenignTotal: totals[level].benignTotal,
			BenignFP:    totals[level].benignFP,
			AttackTotal: totals[level].attackTotal,
			AttackHit:   totals[level].attackHit,
			FPR:         fpr,
			TPR:         tpr,
		}
		t.Logf("Level %d: FPR=%.2f%% (%d/%d), TPR=%.2f%% (%d/%d)",
			level, fpr, totals[level].benignFP, totals[level].benignTotal,
			tpr, totals[level].attackHit, totals[level].attackTotal)
	}
}

func processCybersecLevels(t *testing.T, ds struct {
	name       string
	benignPath string
	attackPath string
	required   bool
	skipShort  bool
}, label, path string, shards, shard int, totals *[6]evalLevelTotals) {
	f, err := openCorpusFile(path)
	if err != nil {
		if ds.required {
			t.Fatalf("Failed to open required file %s: %v", path, err)
		}
		return
	}
	stats, streamErr := forEachCybersecJSONL(f, label, shards, shard, func(tc securitytest.Case) error {
		accumulateParanoiaTotals(t, tc, label, totals)
		return nil
	})
	closeErr := f.Close()
	if streamErr != nil {
		t.Fatalf("Failed to stream paranoia samples from %s: %v", path, streamErr)
	}
	if closeErr != nil {
		t.Fatalf("Failed to close paranoia source %s: %v", path, closeErr)
	}
	if stats.SkippedOverlong > 0 {
		t.Logf("Skipped %d overlong paranoia record(s) from %s", stats.SkippedOverlong, path)
	}
}

func accumulateParanoiaTotals(t *testing.T, tc securitytest.Case, label string, totals *[6]evalLevelTotals) {
	t.Helper()
	hits := detectHitsOnce(t, &tc)
	for level := 0; level <= 5; level++ {
		if label == "benign" {
			totals[level].benignTotal++
			if hitsBlockableAny(hits, level) {
				totals[level].benignFP++
			}
		} else if label == "attack" {
			totals[level].attackTotal++
			if hitsBlockableAny(hits, level) {
				totals[level].attackHit++
			}
		}
	}
}

func detectHitsOnce(t *testing.T, tc *securitytest.Case) []Hit {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		return nil
	}
	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	for k, v := range tc.Header {
		req.Header.Set(k, v)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		return nil
	}
	analyzer := NewAnalyzer("log", 2)
	_, _ = analyzer.Detect(context.Background(), reqCtx)
	if meta, ok := reqCtx.Metadata["semantic_analysis"]; ok {
		if report, ok := meta.(AnalysisReport); ok {
			return report.Hits
		}
	}
	return nil
}

func hitsBlockableAny(hits []Hit, level int) bool {
	analyzer := &Analyzer{paranoiaLevel: level}
	for _, h := range hits {
		if analyzer.blockableHit(h) {
			return true
		}
	}
	return false
}

// detectSampleQuiet runs detection without recording failures (for paranoia-level sweep)
func detectSampleQuiet(analyzer *Analyzer, tc *securitytest.Case) bool {
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

type gzipCorpusFile struct {
	io.Reader
	closers []io.Closer
}

func (g *gzipCorpusFile) Close() error {
	var err error
	for _, c := range g.closers {
		if e := c.Close(); err == nil {
			err = e
		}
	}
	return err
}

func openCorpusFile(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &gzipCorpusFile{Reader: gz, closers: []io.Closer{gz, f}}, nil
	}
	return f, nil
}
