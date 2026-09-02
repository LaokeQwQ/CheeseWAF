package semantic

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/security"
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
// sweep are skipped, but the curated corpus and optional mined probe still run
// so that FPR_GATE / TPR_GATE remain real quality gates. The standalone mined
// probe test is report-only and has its own short-mode opt-in. Do NOT add a
// top-level t.Skip here: it silently turns the CI gate into a no-op.
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
		scope      string
	}{
		{name: "curated_corpus", benignPath: "testdata/curated_external_shapes.jsonl", required: true, skipShort: false, scope: ScopeRequest},
		{name: "mined_probe", benignPath: "testdata/mined_secprose_probe.jsonl", required: false, skipShort: false, scope: ScopeRequest},
		{name: "external_dataset", benignPath: "testdata/cybersec_benign_clean.jsonl", attackPath: "testdata/cybersec_attack_clean.jsonl", required: false, skipShort: true, scope: ScopePayloadOnly},
	}
	governedMode := false
	governedManifestPath := ""
	if governedPath := strings.TrimSpace(os.Getenv("SEMANTIC_EVAL_GOVERNED_CORPUS")); governedPath != "" {
		manifestPath := strings.TrimSpace(os.Getenv("SEMANTIC_EVAL_GOVERNANCE_MANIFEST"))
		if manifestPath == "" {
			t.Fatal("SEMANTIC_EVAL_GOVERNANCE_MANIFEST is required with SEMANTIC_EVAL_GOVERNED_CORPUS")
		}
		governedMode = true
		governedManifestPath = manifestPath
		dataSources = dataSources[:0]
		dataSources = append(dataSources, struct {
			name       string
			benignPath string
			attackPath string
			required   bool
			skipShort  bool
			scope      string
		}{name: "governed_formal_snapshot", benignPath: governedPath, required: true, scope: ScopeRequest})
	}

	report := &EvaluationReport{
		Timestamp:                 time.Now().Format(time.RFC3339),
		Sources:                   make(map[string]*SourceMetrics),
		ByCategory:                make(map[string]*CategoryMetrics),
		ByCategoryAllSources:      make(map[string]*CategoryMetrics),
		ByParanoiaLevel:           make(map[string]*ParanoiaMetrics),
		ByParanoiaLevelAllSources: make(map[string]*ParanoiaMetrics),
		FailedCases:               make([]FailedCase, 0),
	}

	for _, ds := range dataSources {
		if testing.Short() && ds.skipShort {
			t.Logf("Skipping %s in -short mode", ds.name)
			continue
		}

		t.Logf("Processing data source: %s", ds.name)
		if ds.attackPath != "" {
			// Process separate benign and attack files
			processDataSourceSplit(t, analyzer, ds.name, ds.benignPath, ds.attackPath, ds.required, ds.scope, report)
		} else {
			// Process single file with mixed labels
			processDataSource(t, analyzer, ds.name, ds.benignPath, ds.required, governedMode, governedManifestPath, ds.scope, report)
		}
		if governedManifestPath != "" && ds.name == "governed_formal_snapshot" && strings.HasSuffix(strings.ToLower(ds.benignPath), ".gz") {
			t.Fatalf("governed corpus must be uncompressed")
		}
	}

	// Compute aggregate metrics
	computeAggregateMetrics(report)

	// Compute by-paranoia-level metrics. The sweep adds one log-mode pass over
	// every source and re-grades its hits at levels 0-5. It is skipped in -short
	// mode because the external corpus pass is still substantial.
	if testing.Short() {
		t.Log("Skipping by-paranoia-level sweep in -short mode")
	} else {
		computeByParanoiaLevel(t, dataSources, report, governedManifestPath)
	}

	// Add performance metrics from semantic engine
	report.Performance = &PerformanceMetrics{
		ProcessMetrics: ProcessMetrics().Snapshot(),
	}

	// Output JSON report
	outputReport(t, report)

	applyEvaluationGates(t, report)
}

func applyEvaluationGates(t *testing.T, report *EvaluationReport) {
	t.Helper()
	maxFPR, fprEnabled, err := percentGateFromEnv("FPR_GATE")
	if err != nil {
		t.Fatal(err)
	}
	if fprEnabled {
		minimum := positiveEnvInt(t, "FPR_MIN_BENIGN", 100)
		if sumBenignByScope(report.Sources, ScopeRequest) < minimum {
			t.Fatalf("FPR gate requires at least %d request samples, got %d", minimum, sumBenignByScope(report.Sources, ScopeRequest))
		}
		// The acceptance target is strictly below the configured ceiling.
		if report.Overall.FPR >= maxFPR {
			t.Fatalf("FPR gate failed: %.4f%% is not below %.4f%%", report.Overall.FPR, maxFPR)
		}
	}

	minTPR, tprEnabled, err := percentGateFromEnv("TPR_GATE")
	if err != nil {
		t.Fatal(err)
	}
	if tprEnabled {
		minimum := positiveEnvInt(t, "TPR_MIN_ATTACK", 100)
		if sumAttackByScope(report.Sources, ScopeRequest) < minimum {
			t.Fatalf("TPR gate requires at least %d request attack samples, got %d", minimum, sumAttackByScope(report.Sources, ScopeRequest))
		}
		if report.Overall.TPR < minTPR {
			t.Fatalf("TPR gate failed: %.4f%% < %.4f%%", report.Overall.TPR, minTPR)
		}
	}
}

func positiveEnvInt(t *testing.T, name string, fallback int) int {
	t.Helper()
	raw, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 1 {
		t.Fatalf("%s must be a positive integer, got %q", name, raw)
	}
	return value
}

func TestBoundedReaderReportsOverflow(t *testing.T) {
	r := &boundedReader{Reader: strings.NewReader("12345"), max: 4}
	buf := make([]byte, 8)
	if _, err := r.Read(buf); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestLoadGovernedExpectationAcceptsManifestOverOneMiB(t *testing.T) {
	entries := strings.TrimSuffix(strings.Repeat(`"x",`, 300000), ",")
	manifest := fmt.Sprintf(`{"formal":1,"output_hashes":{"formal":"%s"},"missing_optional":[%s]}`,
		strings.Repeat("a", 64), entries)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	expectation := loadGovernedExpectation(t, path)
	if expectation.records != 1 || expectation.hash != strings.Repeat("a", 64) {
		t.Fatalf("unexpected expectation: %+v", expectation)
	}
}

func TestParseGovernedExpectationRejectsManifestOverBound(t *testing.T) {
	if _, err := parseGovernedExpectation(bytes.NewReader(bytes.Repeat([]byte("x"), maxGovernanceManifestBytes+1))); err == nil {
		t.Fatal("expected over-bound manifest rejection")
	}
}

func TestParseGovernedExpectationRejectsUnknownAndDuplicateKeys(t *testing.T) {
	for name, manifest := range map[string]string{
		"unknown":   `{"formal":1,"output_hashes":{"formal":"` + strings.Repeat("a", 64) + `"},"unexpected":1}`,
		"duplicate": `{"formal":1,"Formal":2,"output_hashes":{"formal":"` + strings.Repeat("a", 64) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseGovernedExpectation(strings.NewReader(manifest)); err == nil {
				t.Fatalf("expected %s manifest rejection", name)
			}
		})
	}
}

func TestParseGovernedExpectationRejectsExcessiveNesting(t *testing.T) {
	nested := "0"
	for i := 0; i <= security.DefaultEvaluationArtifactMaxDepth; i++ {
		nested = "[" + nested + "]"
	}
	manifest := `{"formal":1,"output_hashes":{"formal":"` + strings.Repeat("a", 64) + `"},"missing_optional":` + nested + `}`
	if _, err := parseGovernedExpectation(strings.NewReader(manifest)); err == nil {
		t.Fatal("expected excessive manifest nesting rejection")
	}
}

func TestGovernedPassReaderVerifyFailuresAndSuccess(t *testing.T) {
	data := []byte("{}\n")
	h := sha256.Sum256(data)
	makeReader := func(maxBytes int64) (*governedPassReader, security.JSONLStats, string) {
		gr := &governedPassReader{Reader: bytes.NewReader(data), hash: sha256.New(), maxBytes: maxBytes, maxRecords: 1}
		stats, _ := security.ForEachJSONLRaw(gr, 1, 0, nil)
		return gr, stats, hex.EncodeToString(h[:])
	}
	gr, stats, digest := makeReader(2)
	if err := gr.verify(stats, governedExpectation{hash: digest, records: 1}); err == nil {
		t.Fatal("expected byte overflow")
	}
	gr, stats, digest = makeReader(1 << 20)
	if err := gr.verify(stats, governedExpectation{hash: "bad", records: 1}); err == nil {
		t.Fatal("expected hash mismatch")
	}
	if err := gr.verify(stats, governedExpectation{hash: digest, records: 2}); err == nil {
		t.Fatal("expected line mismatch")
	}
	if err := gr.verify(stats, governedExpectation{hash: digest, records: 1}); err != nil {
		t.Fatalf("success verify: %v", err)
	}
	gr = &governedPassReader{Reader: strings.NewReader("{}\n{}\n"), hash: sha256.New(), maxBytes: 1 << 20, maxRecords: 1}
	stats, _ = security.ForEachJSONLRaw(gr, 1, 0, nil)
	if err := gr.verify(stats, governedExpectation{records: 2}); err == nil {
		t.Fatal("expected record overflow")
	}
}

func percentGateFromEnv(name string) (value float64, enabled bool, err error) {
	raw, enabled := os.LookupEnv(name)
	if !enabled {
		return 0, false, nil
	}
	value, err = parsePercentGate(name, raw)
	return value, true, err
}

func parsePercentGate(name, raw string) (float64, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
		return 0, fmt.Errorf("%s must be a finite percentage in [0, 100], got %q", name, raw)
	}
	return value, nil
}

func TestParsePercentGateRejectsInvalidValues(t *testing.T) {
	for _, raw := range []string{"", "nope", "NaN", "+Inf", "-0.1", "100.1", "1 trailing"} {
		if _, err := parsePercentGate("FPR_GATE", raw); err == nil {
			t.Errorf("parsePercentGate(%q) unexpectedly succeeded", raw)
		}
	}
	for _, raw := range []string{"0", "0.8", " 99 ", "100"} {
		if _, err := parsePercentGate("TPR_GATE", raw); err != nil {
			t.Errorf("parsePercentGate(%q): %v", raw, err)
		}
	}
}

func TestPercentGateFromEnvRejectsExplicitBlankValue(t *testing.T) {
	for _, raw := range []string{"", " ", "\t\n"} {
		t.Run(strconv.Quote(raw), func(t *testing.T) {
			t.Setenv("TEST_PERCENT_GATE", raw)
			if _, enabled, err := percentGateFromEnv("TEST_PERCENT_GATE"); !enabled || err == nil {
				t.Fatalf("percentGateFromEnv(%q) = enabled %v, err %v; want enabled with an error", raw, enabled, err)
			}
		})
	}
}

func TestAggregateMetricsSeparatesRequestAndPayloadScopes(t *testing.T) {
	report := &EvaluationReport{Sources: map[string]*SourceMetrics{
		"request": {Scope: ScopeRequest, BenignTotal: 100, BenignFP: 1, AttackTotal: 100, AttackHit: 90},
		"payload": {Scope: ScopePayloadOnly, BenignTotal: 900, BenignFP: 90, AttackTotal: 900, AttackHit: 450},
	}}
	computeAggregateMetrics(report)
	if report.Overall.FPR != 1 || report.Overall.TPR != 90 {
		t.Fatalf("request overall = %+v, want 1%% FPR and 90%% TPR", report.Overall)
	}
	if report.AllSources.FPR != 9.1 || report.AllSources.TPR != 54 {
		t.Fatalf("all-sources = %+v, want 9.1%% FPR and 54%% TPR", report.AllSources)
	}
	if normalizeScope("") != ScopeRequest || normalizeScope("payload-only") != ScopePayloadOnly {
		t.Fatal("scope compatibility/defaulting failed")
	}
	report.ByCategory = map[string]*CategoryMetrics{"sqli": {AttackTotal: 100, AttackHit: 90}}
	report.ByCategoryAllSources = map[string]*CategoryMetrics{"sqli": {AttackTotal: 100, AttackHit: 90}, "xss": {AttackTotal: 900, AttackHit: 450}}
	computeAggregateMetrics(report)
	if _, ok := report.ByCategory["xss"]; ok {
		t.Fatal("payload-only category leaked into primary by_category")
	}
	if _, ok := report.ByCategoryAllSources["xss"]; !ok {
		t.Fatal("payload-only category missing from all-sources diagnostics")
	}
}

func TestSourceScopeSerializes(t *testing.T) {
	report := &EvaluationReport{Sources: map[string]*SourceMetrics{"cybersec": {Scope: ScopePayloadOnly}}}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"scope":"payload-only"`)) {
		t.Fatalf("scope missing: %s", data)
	}
}

func TestCustomSourceNameHonorsExplicitPayloadScope(t *testing.T) {
	report := &EvaluationReport{Sources: map[string]*SourceMetrics{
		"vendor_payload_fixture": {Scope: ScopePayloadOnly, BenignTotal: 10, BenignFP: 10, AttackTotal: 10, AttackHit: 1},
	}}
	computeAggregateMetrics(report)
	if report.Overall.BenignTotal != 0 || report.AllSources.BenignTotal != 10 {
		t.Fatalf("custom payload scope was not separated: overall=%+v all=%+v", report.Overall, report.AllSources)
	}
}

type EvaluationReport struct {
	Timestamp                 string                      `json:"timestamp"`
	Sources                   map[string]*SourceMetrics   `json:"sources"`
	ByCategory                map[string]*CategoryMetrics `json:"by_category"`
	Overall                   EvalMetrics                 `json:"overall"`
	AllSources                EvalMetrics                 `json:"all_sources"`
	ByCategoryAllSources      map[string]*CategoryMetrics `json:"by_category_all_sources,omitempty"`
	ByParanoiaLevel           map[string]*ParanoiaMetrics `json:"by_paranoia_level"`
	ByParanoiaLevelAllSources map[string]*ParanoiaMetrics `json:"by_paranoia_level_all_sources,omitempty"`
	Performance               *PerformanceMetrics         `json:"performance,omitempty"`
	FailedCases               []FailedCase                `json:"failed_cases"`
}

type ParanoiaMetrics struct {
	BenignTotal int     `json:"benign_total"`
	BenignFP    int     `json:"benign_fp"`
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	FPR         float64 `json:"fpr"`
	TPR         float64 `json:"tpr"`
	FPRUpper99  float64 `json:"fpr_upper_99_percent,omitempty"`
	TPRLower99  float64 `json:"tpr_lower_99_percent,omitempty"`
}

type SourceMetrics struct {
	Scope       string      `json:"scope"`
	BenignTotal int         `json:"benign_total"`
	BenignFP    int         `json:"benign_fp"`
	AttackTotal int         `json:"attack_total"`
	AttackHit   int         `json:"attack_hit"`
	EvalMetrics EvalMetrics `json:"metrics"`
}

const (
	ScopeRequest     = "request"
	ScopePayloadOnly = "payload-only"
)

func normalizeScope(scope string) string {
	switch strings.TrimSpace(scope) {
	case ScopePayloadOnly:
		return ScopePayloadOnly
	default:
		return ScopeRequest
	}
}

type CategoryMetrics struct {
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	TPR         float64 `json:"tpr_percent"`
}

type EvalMetrics struct {
	BenignTotal int     `json:"benign_total"`
	BenignFP    int     `json:"benign_fp"`
	AttackTotal int     `json:"attack_total"`
	AttackHit   int     `json:"attack_hit"`
	FPR         float64 `json:"fpr_percent"`
	TPR         float64 `json:"tpr_percent"`
	Precision   float64 `json:"precision_percent"`
	F1Score     float64 `json:"f1_score"`
	FPRUpper99  float64 `json:"fpr_upper_99_percent,omitempty"`
	TPRLower99  float64 `json:"tpr_lower_99_percent,omitempty"`
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

func TestEvaluationDocumentationMatchesModesAndLevels(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/evaluation-platform.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"`-short`",
		"`curated_corpus`",
		"`external_dataset`",
		"levels 0 through 5",
		"`FPR_GATE`",
		"`TPR_GATE`",
		"`SEMANTIC_EVAL_SHARDS`",
		"`merge-semantic-eval-shards.py`",
	} {
		if !bytes.Contains(doc, []byte(required)) {
			t.Errorf("evaluation documentation is missing %q", required)
		}
	}
}

func processDataSource(t *testing.T, analyzer *Analyzer, sourceName, path string, required, governed bool, manifestPath, scope string, report *EvaluationReport) {
	if governed && strings.HasSuffix(strings.ToLower(path), ".gz") {
		t.Fatalf("governed corpus must be uncompressed")
	}
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
	srcMetrics.Scope = normalizeScope(scope)
	report.Sources[sourceName] = srcMetrics

	processed := 0
	var stats security.JSONLStats
	reader := io.Reader(f)
	var governedReader *governedPassReader
	var expectation governedExpectation
	if governed {
		expectation = loadGovernedExpectation(t, manifestPath)
		governedReader = &governedPassReader{Reader: f, hash: sha256.New(), maxBytes: 256 << 20, maxRecords: 1_000_000}
		reader = governedReader
	}
	if required && !governed {
		reader = &boundedReader{Reader: f, max: 256 << 20}
	}
	cb := func(tc security.Case) error {
		processOneSourceCase(t, analyzer, tc, sourceName, governed, report, srcMetrics)
		return nil
	}
	if !governed && !required {
		cb = caseCap(cb, &processed, sourceName)
	}
	stats, err = security.ForEachJSONLWithStats(reader, evalShardTotal(), evalShardIndex(evalShardTotal()), cb)
	capped, decisionErr := corpusStreamDecision(err, required, governed, stats.SkippedOverlong)
	if decisionErr != nil {
		t.Fatalf("Failed to load/stream %s: %v", sourceName, decisionErr)
	}
	if capped {
		t.Logf("Capped %s at %d cases (SEMANTIC_EVAL_MAX_CASES=0 evaluates everything)", sourceName, evalMaxCases())
	}
	if governed {
		if err := governedReader.verify(stats, expectation); err != nil {
			t.Fatal(err)
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

func corpusStreamDecision(streamErr error, required, governed bool, skippedOverlong int) (bool, error) {
	if skippedOverlong > 0 && (required || governed) {
		return false, fmt.Errorf("required corpus contains %d overlong record(s)", skippedOverlong)
	}
	if streamErr == nil {
		return false, nil
	}
	if isCapStop(streamErr) {
		if required || governed {
			return false, fmt.Errorf("required corpus hit evaluation cap")
		}
		return true, nil
	}
	return false, streamErr
}

func TestCorpusStreamDecision(t *testing.T) {
	cases := []struct {
		name               string
		err                error
		required, governed bool
		overlong           int
		capped             bool
		wantErr            bool
	}{
		{"nil", nil, false, false, 0, false, false}, {"error", errors.New("x"), false, false, 0, false, true},
		{"optional cap", errEvalCaseCapReached, false, false, 0, true, false}, {"required cap", errEvalCaseCapReached, true, false, 0, false, true},
		{"required overlong", nil, true, false, 1, false, true}, {"optional overlong", nil, false, false, 1, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capped, err := corpusStreamDecision(tc.err, tc.required, tc.governed, tc.overlong)
			if capped != tc.capped || (err != nil) != tc.wantErr {
				t.Fatalf("got capped=%v err=%v", capped, err)
			}
		})
	}
	br := &boundedReader{Reader: strings.NewReader("12345"), max: 4}
	buf := make([]byte, 8)
	_, err := br.Read(buf)
	if _, decisionErr := corpusStreamDecision(err, true, false, 0); decisionErr == nil {
		t.Fatal("expected bounded overflow to fail closed")
	}
}

type governedExpectation struct {
	hash    string
	records int
}

// Governance manifests are bounded artifacts. The CI projection contract
// allows up to 8 MiB; retain headroom for legitimately large duplicate
// relation arrays while still rejecting unbounded input.
const maxGovernanceManifestBytes = 8 << 20

type governedPassReader struct {
	io.Reader
	hash       hash.Hash
	bytes      int64
	maxBytes   int64
	maxRecords int
}
type boundedReader struct {
	io.Reader
	max, n int64
}

func (r *boundedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += int64(n)
	if r.n > r.max {
		return n, fmt.Errorf("input exceeds %d bytes", r.max)
	}
	return n, err
}

func (r *governedPassReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += int64(n)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	if r.bytes > r.maxBytes {
		return n, fmt.Errorf("governed corpus exceeds %d bytes", r.maxBytes)
	}
	return n, err
}
func (r *governedPassReader) verify(stats security.JSONLStats, e governedExpectation) error {
	if stats.SkippedOverlong > 0 {
		return fmt.Errorf("governed corpus contains %d overlong record(s)", stats.SkippedOverlong)
	}
	if stats.NonEmptyLines > r.maxRecords {
		return fmt.Errorf("governed corpus exceeds %d records", r.maxRecords)
	}
	if r.bytes > r.maxBytes {
		return fmt.Errorf("governed corpus exceeds %d bytes", r.maxBytes)
	}
	if hex.EncodeToString(r.hash.Sum(nil)) != e.hash {
		return fmt.Errorf("governed corpus hash mismatch")
	}
	if stats.NonEmptyLines != e.records {
		return fmt.Errorf("governed corpus line count mismatch: got %d want %d", stats.NonEmptyLines, e.records)
	}
	return nil
}
func loadGovernedExpectation(t *testing.T, path string) governedExpectation {
	t.Helper()
	f, err := openStableCorpusInput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	expectation, err := parseGovernedExpectation(f)
	if err != nil {
		t.Fatal(err)
	}
	return expectation
}

func parseGovernedExpectation(r io.Reader) (governedExpectation, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxGovernanceManifestBytes+1))
	if err != nil || len(b) > maxGovernanceManifestBytes {
		return governedExpectation{}, errors.New("invalid governance manifest")
	}
	if err := validateGovernanceManifestJSON(b); err != nil {
		return governedExpectation{}, fmt.Errorf("invalid governance manifest: %w", err)
	}
	var m security.GovernanceManifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || m.OutputHashes["formal"] == "" || m.Formal <= 0 {
		return governedExpectation{}, errors.New("governance manifest has no formal snapshot")
	}
	return governedExpectation{hash: m.OutputHashes["formal"], records: m.Formal}, nil
}

func validateGovernanceManifestJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("manifest is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkGovernanceJSONValue(dec, 0); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF || tok != nil {
		return errors.New("manifest contains trailing data")
	}
	return nil
}

func walkGovernanceJSONValue(dec *json.Decoder, depth int) error {
	if depth > security.DefaultEvaluationArtifactMaxDepth {
		return fmt.Errorf("manifest exceeds maximum JSON depth %d", security.DefaultEvaluationArtifactMaxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("manifest object key is not a string")
				}
				name = strings.ToLower(name)
				if _, exists := seen[name]; exists {
					return fmt.Errorf("manifest contains duplicate key %q", name)
				}
				seen[name] = struct{}{}
				if err := walkGovernanceJSONValue(dec, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walkGovernanceJSONValue(dec, depth+1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
	}
	return nil
}

func processOneSourceCase(t *testing.T, analyzer *Analyzer, tc security.Case, sourceName string, governed bool, report *EvaluationReport, srcMetrics *SourceMetrics) {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		if governed {
			t.Errorf("Invalid governed request %s: %v", tc.Name, err)
		} else {
			t.Logf("Skipping invalid raw corpus request %s: %v", tc.Name, err)
		}
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
		if governed {
			t.Errorf("Failed to build governed request context for %s: %v", tc.Name, err)
		} else {
			t.Logf("Skipping raw corpus request context %s: %v", tc.Name, err)
		}
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
		if report.ByCategory == nil {
			report.ByCategory = make(map[string]*CategoryMetrics)
		}
		if report.ByCategoryAllSources == nil {
			report.ByCategoryAllSources = make(map[string]*CategoryMetrics)
		}
		catAll := report.ByCategoryAllSources[tc.Category]
		if catAll == nil {
			catAll = &CategoryMetrics{}
		}
		catAll.AttackTotal++
		if detected {
			srcMetrics.AttackHit++
			catAll.AttackHit++
			if normalizeScope(srcMetrics.Scope) == ScopeRequest {
				if report.ByCategory[tc.Category] == nil {
					report.ByCategory[tc.Category] = &CategoryMetrics{}
				}
				report.ByCategory[tc.Category].AttackTotal++
				report.ByCategory[tc.Category].AttackHit++
			}
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
			if normalizeScope(srcMetrics.Scope) == ScopeRequest {
				if report.ByCategory[tc.Category] == nil {
					report.ByCategory[tc.Category] = &CategoryMetrics{}
				}
				report.ByCategory[tc.Category].AttackTotal++
			}
		}
		report.ByCategoryAllSources[tc.Category] = catAll
	}
}

func computeMetrics(benignTotal, benignFP, attackTotal, attackHit int) EvalMetrics {
	m := EvalMetrics{BenignTotal: benignTotal, BenignFP: benignFP, AttackTotal: attackTotal, AttackHit: attackHit}

	// FPR: false positives / total benign
	if benignTotal > 0 {
		m.FPR = float64(benignFP) / float64(benignTotal) * 100
		if _, upper, ok := security.WilsonInterval99(benignFP, benignTotal); ok {
			m.FPRUpper99 = upper * 100
		}
	}

	// TPR (recall): true positives / total attack
	if attackTotal > 0 {
		m.TPR = float64(attackHit) / float64(attackTotal) * 100
		if lower, _, ok := security.WilsonInterval99(attackHit, attackTotal); ok {
			m.TPRLower99 = lower * 100
		}
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
	if report == nil {
		return
	}
	if report.ByCategoryAllSources == nil {
		report.ByCategoryAllSources = make(map[string]*CategoryMetrics)
	}
	var totalBenign, totalBenignFP, totalAttack, totalAttackHit int

	var allBenign, allFP, allAttack, allHit int
	for _, src := range report.Sources {
		allBenign += src.BenignTotal
		allFP += src.BenignFP
		allAttack += src.AttackTotal
		allHit += src.AttackHit
		if normalizeScope(src.Scope) == ScopeRequest {
			totalBenign += src.BenignTotal
			totalBenignFP += src.BenignFP
			totalAttack += src.AttackTotal
			totalAttackHit += src.AttackHit
		}
	}
	report.Overall = computeMetrics(totalBenign, totalBenignFP, totalAttack, totalAttackHit)
	report.AllSources = computeMetrics(allBenign, allFP, allAttack, allHit)

	// Compute per-category TPR
	for cat, metrics := range report.ByCategory {
		if metrics.AttackTotal > 0 {
			metrics.TPR = float64(metrics.AttackHit) / float64(metrics.AttackTotal) * 100
		}
		report.ByCategory[cat] = metrics
	}
	for cat, metrics := range report.ByCategoryAllSources {
		if metrics.AttackTotal > 0 {
			metrics.TPR = float64(metrics.AttackHit) / float64(metrics.AttackTotal) * 100
		}
		report.ByCategoryAllSources[cat] = metrics
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
	fmt.Printf("Request-level Overall FPR: %.4f%% (%d FP / %d benign)\n",
		report.Overall.FPR,
		sumFPByScope(report.Sources, ScopeRequest),
		sumBenignByScope(report.Sources, ScopeRequest),
	)
	if report.Overall.FPRUpper99 > 0 {
		fmt.Printf("FPR 99%% upper bound: %.4f%%\n", report.Overall.FPRUpper99)
	}
	fmt.Printf("Request-level Overall TPR: %.4f%% (%d hit / %d attack)\n",
		report.Overall.TPR,
		sumAttackHitByScope(report.Sources, ScopeRequest),
		sumAttackByScope(report.Sources, ScopeRequest),
	)
	fmt.Printf("All-sources diagnostic FPR: %.4f%%, TPR: %.4f%%\n", report.AllSources.FPR, report.AllSources.TPR)
	if report.Overall.TPRLower99 > 0 {
		fmt.Printf("TPR 99%% lower bound: %.4f%%\n", report.Overall.TPRLower99)
	}
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
				fmt.Printf("Level %d: FPR=%.2f%% (upper99 %.2f%%, %d/%d), TPR=%.2f%% (lower99 %.2f%%, %d/%d)\n",
					level, m.FPR, m.FPRUpper99, m.BenignFP, m.BenignTotal,
					m.TPR, m.TPRLower99, m.AttackHit, m.AttackTotal)
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

func sumBenignByScope(sources map[string]*SourceMetrics, scope string) int {
	total := 0
	for _, s := range sources {
		if normalizeScope(s.Scope) == scope {
			total += s.BenignTotal
		}
	}
	return total
}
func sumFPByScope(sources map[string]*SourceMetrics, scope string) int {
	total := 0
	for _, s := range sources {
		if normalizeScope(s.Scope) == scope {
			total += s.BenignFP
		}
	}
	return total
}
func sumAttackByScope(sources map[string]*SourceMetrics, scope string) int {
	total := 0
	for _, s := range sources {
		if normalizeScope(s.Scope) == scope {
			total += s.AttackTotal
		}
	}
	return total
}
func sumAttackHitByScope(sources map[string]*SourceMetrics, scope string) int {
	total := 0
	for _, s := range sources {
		if normalizeScope(s.Scope) == scope {
			total += s.AttackHit
		}
	}
	return total
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

func processDataSourceSplit(t *testing.T, analyzer *Analyzer, sourceName, benignPath, attackPath string, required bool, scope string, report *EvaluationReport) {
	srcMetrics := &SourceMetrics{}
	srcMetrics.Scope = normalizeScope(scope)
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
			benignProcessed := 0
			var r io.Reader = f
			if required {
				r = &boundedReader{Reader: f, max: 256 << 20}
			}
			cb := func(tc security.Case) error {
				srcMetrics.BenignTotal++
				if detectSample(t, analyzer, &tc, report, sourceName, "benign") {
					srcMetrics.BenignFP++
				}
				return nil
			}
			if !required {
				cb = caseCap(cb, &benignProcessed, sourceName+"/benign")
			}
			stats, streamErr := forEachCybersecJSONL(r, "benign", evalShardTotal(), evalShardIndex(evalShardTotal()), cb)
			capped, decErr := corpusStreamDecision(streamErr, required, false, stats.SkippedOverlong)
			if decErr != nil {
				t.Fatalf("Failed to stream benign samples from %s: %v", benignPath, decErr)
			}
			if capped {
				t.Logf("Capped %s/benign at %d cases (SEMANTIC_EVAL_MAX_CASES=0 evaluates everything)", sourceName, evalMaxCases())
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
			attackProcessed := 0
			var r io.Reader = f
			if required {
				r = &boundedReader{Reader: f, max: 256 << 20}
			}
			cb := func(tc security.Case) error {
				srcMetrics.AttackTotal++
				if report.ByCategoryAllSources == nil {
					report.ByCategoryAllSources = make(map[string]*CategoryMetrics)
				}
				allCat := report.ByCategoryAllSources[tc.Category]
				if allCat == nil {
					allCat = &CategoryMetrics{}
				}
				allCat.AttackTotal++
				if detectSample(t, analyzer, &tc, report, sourceName, "attack") {
					srcMetrics.AttackHit++
					allCat.AttackHit++
					if normalizeScope(srcMetrics.Scope) == ScopeRequest {
						if report.ByCategory[tc.Category] == nil {
							report.ByCategory[tc.Category] = &CategoryMetrics{}
						}
						report.ByCategory[tc.Category].AttackTotal++
						report.ByCategory[tc.Category].AttackHit++
					}
				} else {
					if normalizeScope(srcMetrics.Scope) == ScopeRequest {
						if report.ByCategory[tc.Category] == nil {
							report.ByCategory[tc.Category] = &CategoryMetrics{}
						}
						report.ByCategory[tc.Category].AttackTotal++
					}
				}
				report.ByCategoryAllSources[tc.Category] = allCat
				return nil
			}
			if !required {
				cb = caseCap(cb, &attackProcessed, sourceName+"/attack")
			}
			stats, streamErr := forEachCybersecJSONL(r, "attack", evalShardTotal(), evalShardIndex(evalShardTotal()), cb)
			capped, decErr := corpusStreamDecision(streamErr, required, false, stats.SkippedOverlong)
			if decErr != nil {
				t.Fatalf("Failed to stream attack samples from %s: %v", attackPath, decErr)
			}
			if capped {
				t.Logf("Capped %s/attack at %d cases (SEMANTIC_EVAL_MAX_CASES=0 evaluates everything)", sourceName, evalMaxCases())
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

func forEachCybersecJSONL(r io.Reader, expectedLabel string, shards, shard int, fn func(security.Case) error) (security.JSONLStats, error) {
	return security.ForEachJSONLRaw(r, shards, shard, func(line []byte, lineNo int, selected bool) error {
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
		tc := security.Case{
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
	var got []security.Case
	stats, err := forEachCybersecJSONL(strings.NewReader(long+"\n"+valid+"\n"), "attack", 1, 0, func(tc security.Case) error {
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
		tc := security.Case{
			Name:   fmt.Sprintf("paranoia-raw-shard-%d", i),
			Label:  "benign",
			Method: http.MethodGet,
			Target: "/health",
		}
		line, err := json.Marshal(tc)
		if err != nil {
			t.Fatal(err)
		}
		if security.ShardIndexForRaw(line, shards) == 0 && security.ShardIndexFor(tc.Name, shards) != 0 {
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
		scope      string
	}{{name: "raw_shard", benignPath: path, required: true}}

	computeByParanoiaLevel(t, dataSources, report)
	for level := 0; level <= 5; level++ {
		metrics := report.ByParanoiaLevel[strconv.Itoa(level)]
		if metrics == nil || metrics.BenignTotal != 1 {
			t.Fatalf("level %d metrics=%+v, want one raw-line selected sample", level, metrics)
		}
	}
}

func TestParanoiaSweepSeparatesPayloadOnlyMixedSource(t *testing.T) {
	benign := security.Case{Name: "payload-benign", Label: "benign", Method: http.MethodGet, Target: "/health"}
	attack := security.Case{Name: "payload-attack", Label: "attack", Category: "sqli", Method: http.MethodGet, Target: "/search?q=1%20UNION%20SELECT%20password%20FROM%20users--"}
	var corpus []byte
	for _, tc := range []security.Case{benign, attack} {
		line, err := json.Marshal(tc)
		if err != nil {
			t.Fatal(err)
		}
		corpus = append(corpus, line...)
		corpus = append(corpus, '\n')
	}
	corpusPath := filepath.Join(t.TempDir(), "payload-mixed.jsonl")
	if err := os.WriteFile(corpusPath, corpus, 0o600); err != nil {
		t.Fatal(err)
	}

	dataSources := []struct {
		name       string
		benignPath string
		attackPath string
		required   bool
		skipShort  bool
		scope      string
	}{{name: "payload_mixed", benignPath: corpusPath, required: true, scope: ScopePayloadOnly}}
	report := &EvaluationReport{ByParanoiaLevel: make(map[string]*ParanoiaMetrics)}
	computeByParanoiaLevel(t, dataSources, report)

	for level := 0; level <= 5; level++ {
		key := strconv.Itoa(level)
		primary := report.ByParanoiaLevel[key]
		all := report.ByParanoiaLevelAllSources[key]
		if primary == nil || primary.BenignTotal != 0 || primary.AttackTotal != 0 {
			t.Fatalf("level %d primary metrics=%+v, want no payload-only samples", level, primary)
		}
		if all == nil || all.BenignTotal != 1 || all.AttackTotal != 1 {
			t.Fatalf("level %d all-sources metrics=%+v, want one benign and one attack sample", level, all)
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

func detectSample(t *testing.T, analyzer *Analyzer, tc *security.Case, report *EvaluationReport, sourceName, expectedLabel string) bool {
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
	scope      string
}, report *EvaluationReport, governedManifestPath ...string) {
	if report.ByParanoiaLevel == nil {
		report.ByParanoiaLevel = make(map[string]*ParanoiaMetrics)
	}
	t.Logf("\n===Computing by-paranoia-level metrics (single-pass + offline grading)===")
	var totals [6]evalLevelTotals
	var allTotals [6]evalLevelTotals
	shards := evalShardTotal()
	shard := evalShardIndex(shards)

	for _, ds := range dataSources {
		if testing.Short() && ds.skipShort {
			continue
		}
		if len(governedManifestPath) > 0 && governedManifestPath[0] != "" && ds.name == "governed_formal_snapshot" && strings.HasSuffix(strings.ToLower(ds.benignPath), ".gz") {
			t.Fatalf("governed corpus must be uncompressed")
		}
		if ds.attackPath != "" {
			levelTotals := []*[6]evalLevelTotals{&allTotals}
			if normalizeScope(ds.scope) == ScopeRequest {
				levelTotals = append(levelTotals, &totals)
			}
			processCybersecLevels(t, ds, "benign", ds.benignPath, shards, shard, levelTotals...)
			processCybersecLevels(t, ds, "attack", ds.attackPath, shards, shard, levelTotals...)
			continue
		}
		f, err := openCorpusFile(ds.benignPath)
		if err != nil {
			if ds.required {
				t.Fatalf("Failed to open required benign file %s: %v", ds.benignPath, err)
			}
			continue
		}
		levelTotals := []*[6]evalLevelTotals{&allTotals}
		if normalizeScope(ds.scope) == ScopeRequest {
			levelTotals = append(levelTotals, &totals)
		}
		var levelReader io.Reader = f
		var gr *governedPassReader
		var exp governedExpectation
		if len(governedManifestPath) > 0 && governedManifestPath[0] != "" && ds.name == "governed_formal_snapshot" {
			exp = loadGovernedExpectation(t, governedManifestPath[0])
			gr = &governedPassReader{Reader: f, hash: sha256.New(), maxBytes: 256 << 20, maxRecords: 1_000_000}
			levelReader = gr
		}
		if ds.required && gr == nil {
			levelReader = &boundedReader{Reader: f, max: 256 << 20}
		}
		stats, streamErr := security.ForEachJSONLWithStats(levelReader, shards, shard, func(tc security.Case) error {
			accumulateParanoiaTotals(t, tc, tc.Label, levelTotals...)
			return nil
		})
		closeErr := f.Close()
		_, decErr := corpusStreamDecision(streamErr, ds.required, ds.name == "governed_formal_snapshot", stats.SkippedOverlong)
		if decErr != nil {
			t.Fatalf("Failed to stream paranoia samples from %s: %v", ds.benignPath, decErr)
		}
		if closeErr != nil {
			t.Fatalf("Failed to close paranoia source %s: %v", ds.benignPath, closeErr)
		}
		if stats.SkippedOverlong > 0 {
			t.Logf("Skipped %d overlong paranoia record(s) from %s", stats.SkippedOverlong, ds.benignPath)
		}
		if gr != nil {
			if err := gr.verify(stats, exp); err != nil {
				t.Fatal(err)
			}
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
		if report.ByParanoiaLevelAllSources == nil {
			report.ByParanoiaLevelAllSources = make(map[string]*ParanoiaMetrics)
		}
		am := allTotals[level]
		report.ByParanoiaLevelAllSources[levelKey] = &ParanoiaMetrics{BenignTotal: am.benignTotal, BenignFP: am.benignFP, AttackTotal: am.attackTotal, AttackHit: am.attackHit}
		if am.benignTotal > 0 {
			report.ByParanoiaLevelAllSources[levelKey].FPR = float64(am.benignFP) / float64(am.benignTotal) * 100
		}
		if am.attackTotal > 0 {
			report.ByParanoiaLevelAllSources[levelKey].TPR = float64(am.attackHit) / float64(am.attackTotal) * 100
		}
		if _, upper, ok := security.WilsonInterval99(am.benignFP, am.benignTotal); ok {
			report.ByParanoiaLevelAllSources[levelKey].FPRUpper99 = upper * 100
		}
		if lower, _, ok := security.WilsonInterval99(am.attackHit, am.attackTotal); ok {
			report.ByParanoiaLevelAllSources[levelKey].TPRLower99 = lower * 100
		}
		if _, upper, ok := security.WilsonInterval99(totals[level].benignFP, totals[level].benignTotal); ok {
			report.ByParanoiaLevel[levelKey].FPRUpper99 = upper * 100
		}
		if lower, _, ok := security.WilsonInterval99(totals[level].attackHit, totals[level].attackTotal); ok {
			report.ByParanoiaLevel[levelKey].TPRLower99 = lower * 100
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
	scope      string
}, label, path string, shards, shard int, totals ...*[6]evalLevelTotals) {
	f, err := openCorpusFile(path)
	if err != nil {
		if ds.required {
			t.Fatalf("Failed to open required file %s: %v", path, err)
		}
		return
	}
	var levelReader io.Reader = f
	if ds.required {
		levelReader = &boundedReader{Reader: f, max: 256 << 20}
	}
	stats, streamErr := forEachCybersecJSONL(levelReader, label, shards, shard, func(tc security.Case) error {
		accumulateParanoiaTotals(t, tc, label, totals...)
		return nil
	})
	closeErr := f.Close()
	_, decErr := corpusStreamDecision(streamErr, ds.required, false, stats.SkippedOverlong)
	if decErr != nil {
		t.Fatalf("Failed to stream paranoia samples from %s: %v", path, decErr)
	}
	if closeErr != nil {
		t.Fatalf("Failed to close paranoia source %s: %v", path, closeErr)
	}
	if stats.SkippedOverlong > 0 {
		t.Logf("Skipped %d overlong paranoia record(s) from %s", stats.SkippedOverlong, path)
	}
}

func accumulateParanoiaTotals(t *testing.T, tc security.Case, label string, totals ...*[6]evalLevelTotals) {
	t.Helper()
	hits := detectHitsOnce(t, &tc)
	for _, total := range totals {
		for level := 0; level <= 5; level++ {
			if label == "benign" {
				total[level].benignTotal++
				if hitsBlockableAny(hits, level) {
					total[level].benignFP++
				}
			} else if label == "attack" {
				total[level].attackTotal++
				if hitsBlockableAny(hits, level) {
					total[level].attackHit++
				}
			}
		}
	}
}

func detectHitsOnce(t *testing.T, tc *security.Case) []Hit {
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

func TestParanoiaOfflineGradingMatchesOnlineAcrossSampleShapes(t *testing.T) {
	t.Setenv("CHEESEWAF_SEMANTIC_DEBUG_METADATA", "1")

	const multipartBoundary = "semantic-parity-boundary"
	multipartBody := "--" + multipartBoundary + "\r\n" +
		"Content-Disposition: form-data; name=\"query\"\r\n\r\n" +
		"1 UNION SELECT password FROM users--\r\n" +
		"--" + multipartBoundary + "--\r\n"
	tests := []struct {
		name     string
		caseData security.Case
	}{
		{
			name: "uri",
			caseData: security.Case{Name: "uri", Method: http.MethodGet,
				Target: "/download/%252e%252e/%252e%252e/etc/passwd"},
		},
		{
			name: "query isolated",
			caseData: security.Case{Name: "query-isolated", Method: http.MethodGet,
				Target: "/search?q=1%20UNION%20SELECT%20password%20FROM%20users--"},
		},
		{
			name: "query embedded",
			caseData: security.Case{Name: "query-embedded", Method: http.MethodGet,
				Target: "/notes?text=Observed%20%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D%20in%20logs"},
		},
		{
			name: "header",
			caseData: security.Case{Name: "header", Method: http.MethodGet, Target: "/",
				Header: map[string]string{"X-Query": "1 UNION SELECT password FROM users--"}},
		},
		{
			name: "cookie",
			caseData: security.Case{Name: "cookie", Method: http.MethodGet, Target: "/",
				Header: map[string]string{"Cookie": "query=1%20UNION%20SELECT%20password%20FROM%20users--"}},
		},
		{
			name: "form body",
			caseData: security.Case{Name: "form", Method: http.MethodPost, Target: "/search",
				ContentType: "application/x-www-form-urlencoded", Body: "query=1+UNION+SELECT+password+FROM+users--"},
		},
		{
			name: "json body",
			caseData: security.Case{Name: "json", Method: http.MethodPost, Target: "/search",
				ContentType: "application/json", Body: `{"query":"1 UNION SELECT password FROM users--"}`},
		},
		{
			name: "raw body",
			caseData: security.Case{Name: "raw", Method: http.MethodPost, Target: "/search",
				ContentType: "text/plain", Body: "1 UNION SELECT password FROM users--"},
		},
		{
			name: "multipart body",
			caseData: security.Case{Name: "multipart", Method: http.MethodPost, Target: "/search",
				ContentType: "multipart/form-data; boundary=" + multipartBoundary, Body: multipartBody},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ResetProcessCacheForTest()
			hits := detectHitsOnce(t, &tc.caseData)
			if len(hits) == 0 {
				t.Fatal("sample did not produce any semantic hits")
			}
			for level := 0; level <= 5; level++ {
				offline := hitsBlockableAny(hits, level)
				online := detectSampleQuiet(NewAnalyzer("block", level), &tc.caseData)
				if offline != online {
					t.Fatalf("level %d parity mismatch: offline=%v online=%v hits=%+v", level, offline, online, hits)
				}
			}
		})
	}
}

func TestParanoiaSweepUsesPrimaryEvaluationShardMembership(t *testing.T) {
	const shards = 2
	var corpusLine []byte
	for i := 0; i < 100; i++ {
		tc := security.Case{
			Name:   fmt.Sprintf("shard-parity-%d", i),
			Label:  "benign",
			Method: http.MethodGet,
			Target: "/health",
		}
		line, err := json.Marshal(tc)
		if err != nil {
			t.Fatal(err)
		}
		if security.ShardIndexForRaw(line, shards) == 0 && security.ShardIndexFor(tc.Name, shards) != 0 {
			corpusLine = append(line, '\n')
			break
		}
	}
	if len(corpusLine) == 0 {
		t.Fatal("failed to construct a deterministic raw-line/name shard mismatch")
	}

	corpusPath := filepath.Join(t.TempDir(), "paranoia-shard.jsonl")
	if err := os.WriteFile(corpusPath, corpusLine, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEMANTIC_EVAL_SHARDS", strconv.Itoa(shards))
	t.Setenv("SEMANTIC_EVAL_SHARD_INDEX", "0")
	t.Setenv("CHEESEWAF_SEMANTIC_DEBUG_METADATA", "1")

	dataSources := []struct {
		name       string
		benignPath string
		attackPath string
		required   bool
		skipShort  bool
		scope      string
	}{
		{name: "shard_parity", benignPath: corpusPath, required: true},
	}
	report := &EvaluationReport{ByParanoiaLevel: make(map[string]*ParanoiaMetrics)}
	computeByParanoiaLevel(t, dataSources, report)

	for level := 0; level <= 5; level++ {
		metrics := report.ByParanoiaLevel[strconv.Itoa(level)]
		if metrics == nil || metrics.BenignTotal != 1 {
			t.Fatalf("level %d benign total = %+v, want the one sample selected by the primary raw-line shard", level, metrics)
		}
	}
}

// detectSampleQuiet runs block-mode detection without recording failed cases.
func detectSampleQuiet(analyzer *Analyzer, tc *security.Case) bool {
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

// errEvalCaseCapReached stops corpus streaming once the per-source case budget
// is spent. It is a sentinel: callers check it with errors.Is and treat it as a
// clean stop rather than a corpus failure.
var errEvalCaseCapReached = errors.New("evaluation case cap reached")

// evalMaxCases bounds how many cases a non-short run evaluates per source per
// label. Without it the full cybersec corpus (112MB) never finishes: the test
// hits its timeout and the external_dataset dimension is effectively never
// evaluated.
//
// Set SEMANTIC_EVAL_MAX_CASES=0 to evaluate everything.
func evalMaxCases() int {
	v := strings.TrimSpace(os.Getenv("SEMANTIC_EVAL_MAX_CASES"))
	if v == "" {
		return defaultEvalMaxCases
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultEvalMaxCases
	}
	return n
}

const defaultEvalMaxCases = 20000

// caseCap wraps a corpus callback with a per-label case budget. Returning
// errEvalCaseCapReached aborts the stream, so the cap also avoids reading and
// parsing the rest of a very large file.
func caseCap(fn func(security.Case) error, counter *int, label string) func(security.Case) error {
	limit := evalMaxCases()
	return func(tc security.Case) error {
		if limit > 0 && *counter >= limit {
			return fmt.Errorf("%w (%s)", errEvalCaseCapReached, label)
		}
		*counter++
		return fn(tc)
	}
}

// isCapStop reports whether err is the clean cap stop rather than a real
// corpus failure.
func isCapStop(err error) bool {
	return errors.Is(err, errEvalCaseCapReached)
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
	f, err := openStableCorpusInput(path)
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

// openStableCorpusInput rejects final-component symlinks and closes the
// Lstat/Open race before an evaluation corpus is parsed. A corpus path is an
// evidence identity, not merely a convenient alias; following a mutable link
// could make a baseline report bind one file while replaying another.
func openStableCorpusInput(path string) (*os.File, error) {
	lstat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !lstat.Mode().IsRegular() {
		return nil, fmt.Errorf("corpus must be a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(lstat, info) {
		_ = f.Close()
		return nil, fmt.Errorf("corpus changed while opening: %s", path)
	}
	return f, nil
}
