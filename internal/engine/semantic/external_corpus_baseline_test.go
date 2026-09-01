package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/security"
)

// TestExternalCorpusBaseline measures the semantic engine against the seven
// public corpora that are committed under testdata/ but referenced by no Go
// code. They are historical, quarantine-only research coverage: the corpora
// the CI gate actually sees (curated_corpus, mined_probe) were written against
// this engine, so a green gate there is close to a tautology, while these files
// are not independent blind or release-quality evidence.
//
// This test is deliberately OPT-IN and deliberately NOT a gate:
//
//	SEMANTIC_EXTERNAL_BASELINE=1 go test -run TestExternalCorpusBaseline ./internal/engine/semantic/
//
// It was written to answer "what is the number?" before anyone decides what the
// threshold should be. Turning its rates into a release gate before reading the
// baseline would put the cart before the horse, and silently lowering TPR_GATE
// to make it green would be worse than not measuring at all. The measured rates
// never fail this test, but incomplete input coverage and unexpected analyzer
// errors do fail it so they cannot be mistaken for clean outcomes.
//
// Use SEMANTIC_EXTERNAL_BASELINE_OUT=<path> to also write the JSON report.
func TestExternalCorpusBaseline(t *testing.T) {
	if strings.TrimSpace(os.Getenv("SEMANTIC_EXTERNAL_BASELINE")) != "1" {
		t.Skip("set SEMANTIC_EXTERNAL_BASELINE=1 to measure the unwired external corpora")
	}

	ProcessMetrics().ResetForTest()
	ResetProcessCacheForTest()

	analyzer := NewAnalyzer("block", 2)
	failureDumpPath := strings.TrimSpace(os.Getenv("SEMANTIC_EXTERNAL_BASELINE_FAILS"))
	if err := resetFailureDump(failureDumpPath); err != nil {
		t.Fatalf("prepare external baseline failure dump: %v", err)
	}

	report := &baselineReport{
		Sources:    make(map[string]*baselineSource),
		ByCategory: make(map[string]*CategoryMetrics),
	}
	report.Provenance = collectBaselineProvenance(externalCorpusPaths())
	for name := range externalCorpusPaths() {
		report.Sources[name] = &baselineSource{}
	}

	shards, shard := evalShardTotal(), evalShardIndex(evalShardTotal())

	for _, src := range externalCorpusSources() {
		f, err := openCorpusFile(src.path)
		if err != nil {
			t.Logf("SKIP %s: %v", src.name, err)
			delete(report.Sources, src.name)
			continue
		}
		m := report.Sources[src.name]
		processed := 0
		limit := evalMaxCases()
		fails := &failCollector{path: failureDumpPath}
		stats, err := security.ForEachRawHTTPJSONLPair(f, shards, shard, src.truth,
			func(tc security.Case, raw security.RawHTTPCase) error {
				if limit > 0 && processed >= limit {
					return fmt.Errorf("%w (%s)", errEvalCaseCapReached, src.name)
				}
				processed++
				measureBaselineCase(t, analyzer, tc, raw, report, m, src.name, fails)
				return nil
			})
		if err := fails.Close(); err != nil {
			t.Errorf("writing failure dump for %s: %v", src.name, err)
		}
		f.Close()
		if err != nil && !isCapStop(err) {
			t.Fatalf("failed to stream %s: %v", src.name, err)
		}
		if isCapStop(err) {
			m.Capped = true
		}
		m.SkippedUnadaptable = stats.SkippedUnadaptable
		m.EvalMetrics = computeMetrics(m.BenignTotal, m.BenignFP, m.AttackTotal, m.AttackHit)
	}

	for _, m := range report.Sources {
		report.OverallBenignTotal += m.BenignTotal
		report.OverallBenignFP += m.BenignFP
		report.OverallAttackTotal += m.AttackTotal
		report.OverallAttackHit += m.AttackHit
		report.SkippedUnadaptable += m.SkippedUnadaptable
		report.SkippedUnbuildable += m.SkippedUnbuildable
		report.AnalysisIncomplete += m.AnalysisIncomplete
		report.AnalysisErrors += m.AnalysisErrors
		report.UnexpectedTotal += m.UnexpectedTotal
		report.UnexpectedHit += m.UnexpectedHit
		report.Repaired += m.Repaired
		report.RepairedToBody += m.RepairedToBody
		report.AttackInClass += m.AttackInClass
		report.AttackCrossClass += m.AttackCrossClass
		report.AttackNoEvidence += m.AttackNoEvidence
		report.InClassHit += m.InClassHit
		report.CrossClassHit += m.CrossClassHit
		report.NoEvidenceHit += m.NoEvidenceHit
		report.BenignWithEvidence += m.BenignWithEvidence
		report.FPWithEvidence += m.FPWithEvidence
		report.FPClean += m.FPClean
	}
	if report.AttackInClass > 0 {
		report.TPRLabelCredible = float64(report.InClassHit) / float64(report.AttackInClass) * 100
	}
	if report.AttackNoEvidence > 0 {
		report.TPRLabelNoEvidence = float64(report.NoEvidenceHit) / float64(report.AttackNoEvidence) * 100
	}
	report.OverallMetrics = computeMetrics(
		report.OverallBenignTotal, report.OverallBenignFP,
		report.OverallAttackTotal, report.OverallAttackHit,
	)
	for _, c := range report.ByCategory {
		if c.AttackTotal > 0 {
			c.TPR = float64(c.AttackHit) / float64(c.AttackTotal) * 100
		}
	}
	if report.AnalysisIncomplete > 0 {
		t.Errorf("external baseline omitted %d cases because semantic input coverage was incomplete", report.AnalysisIncomplete)
	}
	if report.AnalysisErrors > 0 {
		t.Errorf("external baseline encountered %d semantic analysis errors", report.AnalysisErrors)
	}

	logBaselineReport(t, report)
	writeBaselineReport(t, report)
}

// TestExternalCorpusBaselineFilesAreCommitted guards the opt-in baseline against
// silent rot: if a corpus is renamed, deleted or emptied, this fails immediately
// instead of letting the measurement quietly shrink.
func TestExternalCorpusBaselineFilesAreCommitted(t *testing.T) {
	for name, path := range externalCorpusPaths() {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("committed corpus %s is missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("committed corpus %s is empty", name)
		}
	}
}

func externalCorpusPaths() map[string]string {
	return map[string]string{
		"ai_waf_attack":            filepath.Join("testdata", "ai_waf_attack_clean.jsonl"),
		"ai_waf_benign":            filepath.Join("testdata", "ai_waf_benign_clean.jsonl"),
		"httpparams_attack":        filepath.Join("testdata", "httpparams_attack_clean.jsonl"),
		"httpparams_benign":        filepath.Join("testdata", "httpparams_benign_clean.jsonl"),
		"waf_detection_attack":     filepath.Join("testdata", "waf_detection_attack_clean.jsonl"),
		"aetherguard_attack":       filepath.Join("testdata", "aetherguard_attack_clean.jsonl"),
		"aetherguard_undetectable": filepath.Join("testdata", "aetherguard_undetectable.jsonl"),
	}
}

// externalCorpusSources returns the corpora in a deterministic order with the
// ground truth each file carries. These datasets split benign and attack into
// separate files instead of labelling each record, so the truth comes from the
// file, not the row.
func externalCorpusSources() []externalCorpusSource {
	paths := externalCorpusPaths()
	order := []string{
		"ai_waf_attack", "ai_waf_benign",
		"httpparams_attack", "httpparams_benign",
		"waf_detection_attack",
		"aetherguard_attack", "aetherguard_undetectable",
	}
	out := make([]externalCorpusSource, 0, len(order))
	for _, name := range order {
		truth := "attack"
		if strings.HasSuffix(name, "_benign") {
			truth = "benign"
		}
		out = append(out, externalCorpusSource{name: name, path: paths[name], truth: truth})
	}
	return out
}

type externalCorpusSource struct {
	name  string
	path  string
	truth string
}

type baselineSource struct {
	SourceMetrics
	// SkippedUnadaptable counts records the adapter could not turn into a
	// request at all (unparseable targets). SkippedUnbuildable counts records
	// the engine refused (oversized bodies). Both are reported because dropping
	// attack samples without counting them inflates TPR.
	SkippedUnadaptable int `json:"skipped_unadaptable"`
	SkippedUnbuildable int `json:"skipped_unbuildable"`
	// AnalysisIncomplete is distinct from adapter/build skips: the request was
	// constructed, but the analyzer could not cover its input completely. It is
	// never included in a quality denominator. AnalysisErrors are unexpected
	// analyzer failures and likewise cannot be treated as clean outcomes.
	AnalysisIncomplete int  `json:"analysis_incomplete"`
	AnalysisErrors     int  `json:"analysis_errors"`
	Capped             bool `json:"capped"`
	// UnexpectedTotal/Hit track the subset aetherguard itself marks as not
	// expected to be detected. They are a subset of AttackTotal.
	UnexpectedTotal int `json:"upstream_unexpected_total"`
	UnexpectedHit   int `json:"upstream_unexpected_hit"`
	// Repaired and RepairedToBody count rows the adapter had to rebuild before
	// they could be measured at all. They are measured, not dropped: silently
	// shrinking the attack denominator is what makes a corpus look clean.
	Repaired       int `json:"repaired_split_payload"`
	RepairedToBody int `json:"repaired_to_body"`

	// Label fidelity, measured with security.FidelityOf. The corpora assign
	// their own attack classes and nothing verifies them, so a low TPR can mean
	// either a detection gap or a bookkeeping gap. These counters separate the
	// two. InClass/CrossClass/NoEvidence partition AttackTotal;
	// Evidence/NoEvidence partition BenignTotal.
	AttackInClass    int `json:"attack_label_in_class"`
	AttackCrossClass int `json:"attack_label_cross_class"`
	AttackNoEvidence int `json:"attack_label_no_evidence"`
	// Hits within each fidelity bucket, so a TPR can be recomputed per bucket.
	InClassHit    int `json:"attack_label_in_class_hit"`
	CrossClassHit int `json:"attack_label_cross_class_hit"`
	NoEvidenceHit int `json:"attack_label_no_evidence_hit"`
	// Benign rows that carry some attack signature. This is a lead, not a
	// verdict: "how do I escape a <script> tag" is ordinary prose that matches
	// an XSS signature. Reported so a false positive can be re-read in context
	// instead of being taken at face value.
	BenignWithEvidence int `json:"benign_with_attack_signature"`
	FPWithEvidence     int `json:"fp_on_row_with_attack_signature"`
	FPClean            int `json:"fp_on_row_without_attack_signature"`
}

type baselineReport struct {
	Provenance         baselineProvenance          `json:"provenance"`
	Sources            map[string]*baselineSource  `json:"sources"`
	ByCategory         map[string]*CategoryMetrics `json:"by_category"`
	OverallMetrics     EvalMetrics                 `json:"overall"`
	OverallBenignTotal int                         `json:"overall_benign_total"`
	OverallBenignFP    int                         `json:"overall_benign_fp"`
	OverallAttackTotal int                         `json:"overall_attack_total"`
	OverallAttackHit   int                         `json:"overall_attack_hit"`
	SkippedUnadaptable int                         `json:"skipped_unadaptable"`
	SkippedUnbuildable int                         `json:"skipped_unbuildable"`
	AnalysisIncomplete int                         `json:"analysis_incomplete"`
	AnalysisErrors     int                         `json:"analysis_errors"`
	UnexpectedTotal    int                         `json:"upstream_unexpected_total"`
	UnexpectedHit      int                         `json:"upstream_unexpected_hit"`
	Repaired           int                         `json:"repaired_split_payload"`
	RepairedToBody     int                         `json:"repaired_to_body"`

	// Fidelity totals across sources, plus the recomputed TPR for the subset
	// whose label the payload actually supports.
	AttackInClass      int     `json:"attack_label_in_class"`
	AttackCrossClass   int     `json:"attack_label_cross_class"`
	AttackNoEvidence   int     `json:"attack_label_no_evidence"`
	InClassHit         int     `json:"attack_label_in_class_hit"`
	CrossClassHit      int     `json:"attack_label_cross_class_hit"`
	NoEvidenceHit      int     `json:"attack_label_no_evidence_hit"`
	TPRLabelCredible   float64 `json:"tpr_label_credible_pct"`
	TPRLabelNoEvidence float64 `json:"tpr_label_no_evidence_pct"`
	BenignWithEvidence int     `json:"benign_with_attack_signature"`
	FPWithEvidence     int     `json:"fp_on_row_with_attack_signature"`
	FPClean            int     `json:"fp_on_row_without_attack_signature"`
}

// baselineFailCase is one wrongly graded sample. Seeing them is the only way to
// tell a systematic detection gap from corpus noise, so the harness can dump
// every failure to disk rather than just counting them.
type baselineFailCase struct {
	Source   string `json:"source"`
	Type     string `json:"type"` // "FP", "FN", "INCOMPLETE", or "ERROR"
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Method   string `json:"method"`
	Target   string `json:"target"`
	Body     string `json:"body"`
	Error    string `json:"error,omitempty"`
	// Headers are dumped because these corpora hide payloads outside the
	// request line: an ai_waf row carries only an ordinary profile update in
	// its URL and body while the actual time-based blind injection sits in a
	// Cookie value. Without this field that row reads as an inexplicable false
	// positive, which is exactly how it was first misread.
	Headers map[string]string `json:"headers,omitempty"`
	// Evidence is the fidelity verdict's class list, so a reader can tell a row
	// the corpus mislabelled from a row the engine genuinely missed.
	Evidence []string `json:"evidence,omitempty"`
}

// failCollector writes every failure to JSONL when a path is configured. Each
// source appends to the same file, so one run produces one complete dump.
type failCollector struct {
	path string
	file *os.File
	enc  *json.Encoder
	err  error
}

// resetFailureDump starts a fresh opt-in baseline run. The collector is
// intentionally append-only while sources are streamed so one source cannot
// erase another; resetting once before the source loop prevents a reused path
// from retaining stale failures from an earlier run.
func resetFailureDump(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("failure dump path must not be a symlink: %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("failure dump path must be a regular file: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect failure dump path: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("truncate failure dump: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close truncated failure dump: %w", err)
	}
	return nil
}

func (c *failCollector) add(fc baselineFailCase) {
	if c.path == "" || c.err != nil {
		return
	}
	if c.file == nil {
		f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			c.err = fmt.Errorf("open failure dump: %w", err)
			return
		}
		c.file = f
		c.enc = json.NewEncoder(f)
	}
	if err := c.enc.Encode(fc); err != nil {
		c.err = fmt.Errorf("write failure dump: %w", err)
	}
}

func (c *failCollector) Close() error {
	var closeErr error
	if c.file != nil {
		closeErr = c.file.Close()
		c.file = nil
	}
	if c.err != nil && closeErr != nil {
		return errors.Join(c.err, closeErr)
	}
	if c.err != nil {
		return c.err
	}
	return closeErr
}

func TestResetFailureDumpReplacesStaleRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failures.jsonl")
	if err := os.WriteFile(path, []byte(`{"source":"old","type":"FN"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed stale failure dump: %v", err)
	}
	if err := resetFailureDump(path); err != nil {
		t.Fatalf("reset failure dump: %v", err)
	}

	collector := &failCollector{path: path}
	collector.add(baselineFailCase{Source: "current", Type: "FP", Name: "fresh"})
	if err := collector.Close(); err != nil {
		t.Fatalf("close failure dump: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failure dump: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("stale rows were retained: got %d lines (%q)", len(lines), string(data))
	}
	var got baselineFailCase
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("decode current failure row: %v", err)
	}
	if got.Source != "current" || got.Name != "fresh" {
		t.Fatalf("unexpected current failure row: %+v", got)
	}
}

func TestResetFailureDumpRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	link := filepath.Join(dir, "failures.jsonl")
	if err := os.WriteFile(target, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := resetFailureDump(link); err == nil {
		t.Fatal("symlink failure dump path was accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "sentinel\n" {
		t.Fatalf("symlink target was modified: %q", string(data))
	}
}

func TestFailCollectorReportsOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "failures.jsonl")
	collector := &failCollector{path: path}
	collector.add(baselineFailCase{Source: "current", Type: "FP", Name: "fresh"})
	if err := collector.Close(); err == nil {
		t.Fatal("failure dump open error was swallowed")
	}
}

func measureBaselineCase(t *testing.T, analyzer *Analyzer, tc security.Case, raw security.RawHTTPCase, report *baselineReport, m *baselineSource, sourceName string, fails *failCollector) {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		m.SkippedUnbuildable++
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
		// Oversized bodies and similar are the engine declining the sample, not
		// a detection outcome.
		m.SkippedUnbuildable++
		return
	}

	res, err := analyzer.Detect(context.Background(), reqCtx)
	if err != nil {
		failureType := "ERROR"
		if errors.Is(err, ErrSemanticInputIncomplete) {
			m.AnalysisIncomplete++
			failureType = "INCOMPLETE"
		} else {
			m.AnalysisErrors++
		}
		fails.add(baselineFailCase{
			Source: sourceName, Type: failureType, Name: tc.Name, Category: tc.Category,
			Method: tc.Method, Target: clip(tc.Target), Body: clip(tc.Body),
			Headers: tc.Header, Evidence: security.FidelityOf(tc).Classes, Error: clip(err.Error()),
		})
		return
	}
	detected := res != nil && res.Detected

	switch tc.Rationale {
	case security.RationaleRepairedSplitPayload:
		m.Repaired++
	case security.RationaleRepairedToBody:
		m.RepairedToBody++
	}

	// aetherguard marks 34 samples its own dataset does not expect a WAF to
	// catch. Report them separately so they do not quietly deflate the headline
	// TPR without explanation.
	upstreamUnexpected := raw.ExpectedDetection != nil && !*raw.ExpectedDetection

	got := "not_detected"
	if detected && res != nil {
		got = fmt.Sprintf("%s (conf=%.2f)", res.Category, res.Confidence)
	}

	verdict := security.FidelityOf(tc)

	switch tc.Label {
	case "benign":
		m.BenignTotal++
		if !verdict.NoEvidence {
			m.BenignWithEvidence++
		}
		if detected {
			m.BenignFP++
			if verdict.NoEvidence {
				m.FPClean++
			} else {
				m.FPWithEvidence++
			}
			fails.add(baselineFailCase{
				Source: sourceName, Type: "FP", Name: tc.Name, Category: got,
				Method: tc.Method, Target: clip(tc.Target), Body: clip(tc.Body),
				Headers: tc.Header, Evidence: verdict.Classes,
			})
		}
	case "attack":
		m.AttackTotal++
		if upstreamUnexpected {
			m.UnexpectedTotal++
		}
		switch {
		case verdict.InClass:
			m.AttackInClass++
		case verdict.NoEvidence:
			m.AttackNoEvidence++
		default:
			m.AttackCrossClass++
		}
		if report.ByCategory[tc.Category] == nil {
			report.ByCategory[tc.Category] = &CategoryMetrics{}
		}
		report.ByCategory[tc.Category].AttackTotal++
		if detected {
			m.AttackHit++
			report.ByCategory[tc.Category].AttackHit++
			if upstreamUnexpected {
				m.UnexpectedHit++
			}
			switch {
			case verdict.InClass:
				m.InClassHit++
			case verdict.NoEvidence:
				m.NoEvidenceHit++
			default:
				m.CrossClassHit++
			}
		} else {
			fails.add(baselineFailCase{
				Source: sourceName, Type: "FN", Name: tc.Name, Category: tc.Category,
				Method: tc.Method, Target: clip(tc.Target), Body: clip(tc.Body),
				Headers: tc.Header, Evidence: verdict.Classes,
			})
		}
	}
}

// pct guards the divide-by-zero that a per-source or per-bucket breakdown hits
// whenever a corpus contributes no rows to a bucket.
func pct(hit, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(hit) / float64(total) * 100
}

// clip keeps failure dumps readable; the samples are attacker payloads and a
// single record can be megabytes of padding.
func clip(s string) string {
	const max = 400
	if len(s) > max {
		return s[:max] + "...[clipped]"
	}
	return s
}

func logBaselineReport(t *testing.T, report *baselineReport) {
	t.Log("=== external corpus baseline (opt-in measurement, not a gate) ===")
	names := make([]string, 0, len(report.Sources))
	for name := range report.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m := report.Sources[name]
		t.Logf("%-26s benign %6d (FP %5d, FPR %6.3f%%)  attack %6d (hit %5d, TPR %6.2f%%)  skipped: adapt=%d build=%d  repaired=%d capped=%v",
			name, m.BenignTotal, m.BenignFP, m.EvalMetrics.FPR,
			m.AttackTotal, m.AttackHit, m.EvalMetrics.TPR,
			m.SkippedUnadaptable, m.SkippedUnbuildable, m.Repaired+m.RepairedToBody, m.Capped)
		if m.AnalysisIncomplete > 0 || m.AnalysisErrors > 0 {
			t.Logf("%-26s   ↳ omitted from rates: incomplete=%d errors=%d", "", m.AnalysisIncomplete, m.AnalysisErrors)
		}
		if m.UnexpectedTotal > 0 {
			t.Logf("%-26s   ↳ upstream-unexpected subset: %d samples, %d detected (%.2f%%)",
				"", m.UnexpectedTotal, m.UnexpectedHit,
				float64(m.UnexpectedHit)/float64(m.UnexpectedTotal)*100)
		}
		if m.AttackTotal > 0 {
			// fidelity := is the payload's own attack class the one the corpus
			// filed it under? A low number means the corpus label, not the
			// engine, is what cannot see the attack.
			fidelity := float64(m.AttackInClass) / float64(m.AttackTotal) * 100
			t.Logf("%-26s   ↳ label fidelity: in-class %d (%.1f%%) cross-class %d no-evidence %d  |  TPR: in-class %.2f%% cross-class %.2f%% no-evidence %.2f%%",
				"", m.AttackInClass, fidelity, m.AttackCrossClass, m.AttackNoEvidence,
				pct(m.InClassHit, m.AttackInClass), pct(m.CrossClassHit, m.AttackCrossClass),
				pct(m.NoEvidenceHit, m.AttackNoEvidence))
		}
		if m.BenignTotal > 0 && m.BenignFP > 0 {
			t.Logf("%-26s   ↳ benign rows carrying an attack signature: %d (%.2f%%); of %d FPs, %d fired on such a row and %d on a clean one",
				"", m.BenignWithEvidence, pct(m.BenignWithEvidence, m.BenignTotal),
				m.BenignFP, m.FPWithEvidence, m.FPClean)
		}
	}

	// The headline interpretation. Both numbers are the same engine over the
	// same rows; only the denominator differs.
	t.Logf("LABEL FIDELITY: attack rows whose payload supports their label: %d/%d (%.1f%%)",
		report.AttackInClass, report.OverallAttackTotal, pct(report.AttackInClass, report.OverallAttackTotal))
	t.Logf("  TPR as labelled (all attack rows)      : %.2f%%  [%d/%d]",
		report.OverallMetrics.TPR, report.OverallAttackHit, report.OverallAttackTotal)
	t.Logf("  TPR on label-credible rows only        : %.2f%%  [%d/%d]  <- the detection number",
		report.TPRLabelCredible, report.InClassHit, report.AttackInClass)
	t.Logf("  TPR on rows with no attack evidence    : %.2f%%  [%d/%d]  <- near zero by construction; higher means the engine sees what the signature set does not",
		report.TPRLabelNoEvidence, report.NoEvidenceHit, report.AttackNoEvidence)
	t.Logf("  cross-class rows (evidence, wrong label): %d, detected %.2f%%",
		report.AttackCrossClass, pct(report.CrossClassHit, report.AttackCrossClass))
	t.Logf("  benign rows carrying an attack signature: %d/%d (%.2f%%)",
		report.BenignWithEvidence, report.OverallBenignTotal, pct(report.BenignWithEvidence, report.OverallBenignTotal))
	t.Logf("  false positives: %d total, %d on a row with an attack signature, %d on a clean row (FPR on clean rows %.3f%%)",
		report.OverallBenignFP, report.FPWithEvidence, report.FPClean,
		pct(report.FPClean, report.OverallBenignTotal-report.BenignWithEvidence))

	cats := make([]string, 0, len(report.ByCategory))
	for cat := range report.ByCategory {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		c := report.ByCategory[cat]
		t.Logf("  category %-14s attack %6d  hit %6d  TPR %6.2f%%", cat, c.AttackTotal, c.AttackHit, c.TPR)
	}

	t.Logf("OVERALL benign %d (FP %d, FPR %.3f%%)  attack %d (hit %d, TPR %.2f%%)",
		report.OverallBenignTotal, report.OverallBenignFP, report.OverallMetrics.FPR,
		report.OverallAttackTotal, report.OverallAttackHit, report.OverallMetrics.TPR)
	if report.SkippedUnadaptable > 0 || report.SkippedUnbuildable > 0 {
		t.Logf("DROPPED (not counted in any rate above): unadaptable=%d unbuildable=%d — these make the headline look BETTER than reality",
			report.SkippedUnadaptable, report.SkippedUnbuildable)
	}
	if report.AnalysisIncomplete > 0 || report.AnalysisErrors > 0 {
		t.Logf("OMITTED (not counted in any rate above): incomplete=%d errors=%d — coverage failures are not clean outcomes",
			report.AnalysisIncomplete, report.AnalysisErrors)
	}
	if report.UnexpectedTotal > 0 {
		t.Logf("upstream-unexpected subset: %d samples, %d detected (%.2f%%)",
			report.UnexpectedTotal, report.UnexpectedHit,
			float64(report.UnexpectedHit)/float64(report.UnexpectedTotal)*100)
	}
	if report.Repaired > 0 || report.RepairedToBody > 0 {
		t.Logf("REPAIRED (measured, not dropped): %d split-payload rows rebuilt, %d unroutable targets moved to body",
			report.Repaired, report.RepairedToBody)
	}
}

func writeBaselineReport(t *testing.T, report *baselineReport) {
	out := strings.TrimSpace(os.Getenv("SEMANTIC_EXTERNAL_BASELINE_OUT"))
	if out == "" {
		return
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Errorf("marshal baseline report: %v", err)
		return
	}
	if err := writeBaselineReportFile(out, append(data, '\n')); err != nil {
		t.Errorf("write baseline report to %s: %v", out, err)
		return
	}
	t.Logf("wrote baseline report to %s", out)
}

// writeBaselineReportFile writes a report without following a final-component
// symlink and without exposing a partially-written JSON document. The report
// path is opt-in and user-controlled; keeping its safety contract aligned with
// the failure-dump path prevents an accidental overwrite outside the intended
// output file when a stale symlink is reused.
func writeBaselineReportFile(path string, data []byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("baseline report path must not be empty")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("baseline report path must not be a symlink: %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("baseline report path must be a regular file: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect baseline report path: %w", err)
	}

	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".semantic-baseline-report.*")
	if err != nil {
		return fmt.Errorf("create temporary baseline report: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("restrict temporary baseline report: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary baseline report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary baseline report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary baseline report: %w", err)
	}
	if err := installBaselineReport(temporaryName, path, parent); err != nil {
		return fmt.Errorf("install baseline report: %w", err)
	}
	removeTemporary = false
	return nil
}

// Windows' MoveFile call does not replace an existing destination. Move the
// already-validated regular file aside there, then restore it if installation
// fails. Unix-like platforms retain the single atomic rename path.
func installBaselineReport(temporaryName, path, parent string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(temporaryName, path)
	}

	backupName, err := moveExistingBaselineReportAside(path, parent)
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		if backupName != "" {
			if restoreErr := os.Rename(backupName, path); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous baseline report: %w", restoreErr))
			}
		}
		return err
	}
	if backupName != "" {
		_ = os.Remove(backupName)
	}
	return nil
}

func moveExistingBaselineReportAside(path, parent string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect existing baseline report: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("baseline report path must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("baseline report path must be a regular file: %s", path)
	}

	placeholder, err := os.CreateTemp(parent, ".semantic-baseline-report-backup.*")
	if err != nil {
		return "", fmt.Errorf("create baseline report backup placeholder: %w", err)
	}
	backupName := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(backupName)
		return "", fmt.Errorf("close baseline report backup placeholder: %w", err)
	}
	if err := os.Remove(backupName); err != nil {
		return "", fmt.Errorf("remove baseline report backup placeholder: %w", err)
	}
	if err := os.Rename(path, backupName); err != nil {
		return "", fmt.Errorf("move existing baseline report aside: %w", err)
	}
	return backupName, nil
}
