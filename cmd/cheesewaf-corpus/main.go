package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/security"
)

type result struct {
	Name             string  `json:"name"`
	SourceFamily     string  `json:"source_family,omitempty"`
	Label            string  `json:"label"`
	Category         string  `json:"category,omitempty"`
	Rationale        string  `json:"rationale,omitempty"`
	Mode             string  `json:"mode"`
	Method           string  `json:"method"`
	Target           string  `json:"target"`
	StatusCode       int     `json:"status_code,omitempty"`
	Blocked          bool    `json:"blocked,omitempty"`
	Detected         bool    `json:"detected,omitempty"`
	DetectorCategory string  `json:"detector_category,omitempty"`
	DetectorID       string  `json:"detector_id,omitempty"`
	Message          string  `json:"message,omitempty"`
	LatencyMS        float64 `json:"latency_ms"`
	Passed           bool    `json:"passed"`
	Warning          bool    `json:"warning,omitempty"`
	Error            string  `json:"error,omitempty"`
}

type summary struct {
	Mode              string        `json:"mode"`
	Corpus            string        `json:"corpus"`
	BaseURL           string        `json:"base_url,omitempty"`
	StartedAt         time.Time     `json:"started_at"`
	DurationMS        float64       `json:"duration_ms"`
	Total             int           `json:"total"`
	AttackTotal       int           `json:"attack_total"`
	AttackDetected    int           `json:"attack_detected"`
	AttackMissed      int           `json:"attack_missed"`
	BenignTotal       int           `json:"benign_total"`
	BenignClean       int           `json:"benign_clean"`
	FalsePositive     int           `json:"false_positive"`
	Warnings          int           `json:"warnings"`
	Failures          int           `json:"failures"`
	DetectionRate     float64       `json:"detection_rate"`
	FalsePositiveRate float64       `json:"false_positive_rate"`
	Results           []result      `json:"results"`
	ExternalSuites    []suiteResult `json:"external_suites,omitempty"`
}

// splitEvaluationReport is intentionally separate from the legacy replay
// summary. It records request-level quality metrics for exactly one immutable
// partition and never mixes train/validation/blind denominators.
type splitEvaluationReport struct {
	Version             string                          `json:"version"`
	Mode                string                          `json:"mode"`
	Artifact            string                          `json:"artifact"`
	ArtifactSHA256      string                          `json:"artifact_sha256"`
	ManifestSHA256      string                          `json:"governance_manifest_sha256,omitempty"`
	ManifestPayloadHash string                          `json:"governance_manifest_payload_hash,omitempty"`
	FormalSHA256        string                          `json:"governance_formal_sha256,omitempty"`
	SplitInputSHA256    string                          `json:"split_input_sha256,omitempty"`
	Split               security.EvaluationSplit        `json:"split"`
	StartedAt           time.Time                       `json:"started_at"`
	DurationMS          float64                         `json:"duration_ms"`
	InputRecords        int                             `json:"input_records"`
	EvaluatedRecords    int                             `json:"evaluated_records"`
	Groups              int                             `json:"groups"`
	Repaired            bool                            `json:"repaired,omitempty"`
	AttackTotal         int                             `json:"attack_total"`
	AttackDetected      int                             `json:"attack_detected"`
	AttackMissed        int                             `json:"attack_missed"`
	BenignTotal         int                             `json:"benign_total"`
	BenignClean         int                             `json:"benign_clean"`
	FalsePositive       int                             `json:"false_positive"`
	CategoryMismatches  int                             `json:"category_mismatches"`
	Failures            int                             `json:"failures"`
	FPRPercent          float64                         `json:"fpr_percent"`
	TPRPercent          float64                         `json:"tpr_percent"`
	PrecisionPercent    float64                         `json:"precision_percent"`
	F1Score             float64                         `json:"f1_score"`
	FPRUpper99Percent   float64                         `json:"fpr_upper_99_percent,omitempty"`
	TPRLower99Percent   float64                         `json:"tpr_lower_99_percent,omitempty"`
	Sources             map[string]splitSourceMetrics   `json:"sources"`
	Categories          map[string]splitCategoryMetrics `json:"categories,omitempty"`
	Results             []result                        `json:"results"`
}

type splitSourceMetrics struct {
	BenignTotal    int     `json:"benign_total"`
	BenignFP       int     `json:"benign_fp"`
	AttackTotal    int     `json:"attack_total"`
	AttackDetected int     `json:"attack_detected"`
	FPRPercent     float64 `json:"fpr_percent"`
	TPRPercent     float64 `json:"tpr_percent"`
}

type splitCategoryMetrics struct {
	AttackTotal    int     `json:"attack_total"`
	AttackDetected int     `json:"attack_detected"`
	TPRPercent     float64 `json:"tpr_percent"`
}

type options struct {
	Mode                   string
	CorpusPath             string
	GovernanceConfigPath   string
	GovernanceManifestPath string
	GovernanceFormalPath   string
	SplitConfigPath        string
	EvaluationSplit        string
	ExpectedArtifactSHA256 string
	MaxRecords             int
	MaxBytes               int64
	AllowUngoverned        bool
	BaseURL                string
	AdminURL               string
	Timeout                time.Duration
	ToolTimeout            time.Duration
	Insecure               bool
	BlockStatuses          string
	OutputPath             string
	NucleiTemplates        string
	RequireExternal        bool
	SkipExternal           bool
	Workers                int
	Shards                 int
	Shard                  int
	Stream                 bool
	Progress               bool
}

func main() {
	var (
		mode               = flag.String("mode", "analyzer", "validation mode: analyzer, http, gate, govern, split, or evaluate-split")
		corpusPath         = flag.String("corpus", "internal/engine/semantic/testdata/curated_external_shapes.jsonl", "JSONL corpus path")
		governanceConfig   = flag.String("governance-config", "", "local JSON corpus governance configuration")
		governanceManifest = flag.String("governance-manifest", "", "local governance manifest binding a formal split input")
		governanceFormal   = flag.String("governance-formal", "", "local formal governance snapshot when split input is a metadata envelope")
		splitConfig        = flag.String("split-config", "", "local JSON group-aware evaluation split configuration")
		evaluationSplit    = flag.String("evaluation-split", "", "partition to evaluate in evaluate-split mode: train, validation, or blind")
		expectedArtifact   = flag.String("expected-artifact-sha256", "", "expected lowercase SHA-256 of the complete evaluation split artifact")
		maxRecords         = flag.Int("max-records", 0, "maximum evaluation records for split mode (0 = finite default)")
		maxBytes           = flag.Int64("max-bytes", 0, "maximum decompressed evaluation JSONL bytes for split mode (0 = finite default)")
		allowUngoverned    = flag.Bool("allow-ungoverned", false, "explicitly allow hand-authored evaluation rows without governance provenance in split mode")
		baseURL            = flag.String("base-url", "", "base URL for http/gate mode, for example http://127.0.0.1:8080")
		adminURL           = flag.String("admin-url", "", "admin-plane base URL for gate mode; defaults to base URL when empty")
		timeout            = flag.Duration("timeout", 10*time.Second, "per-request timeout in http mode")
		toolTimeout        = flag.Duration("tool-timeout", 10*time.Minute, "per-tool timeout in gate mode")
		insecure           = flag.Bool("insecure", false, "skip TLS certificate verification in http mode and supported gate scanners")
		blockStatuses      = flag.String("block-statuses", "403,406,429,451,503", "comma-separated statuses treated as WAF block/challenge")
		outputPath         = flag.String("output", "", "write JSON report to file instead of stdout")
		nucleiTemplates    = flag.String("nuclei-templates", "security-validation/nuclei", "nuclei template directory for gate mode")
		requireExternal    = flag.Bool("require-external", false, "fail gate mode when an external scanner is missing instead of skipping")
		skipExternal       = flag.Bool("skip-external", false, "skip external scanner wrappers in gate mode and run only analyzer/http replay")
		workers            = flag.Int("workers", 0, "concurrent workers for analyzer/http replay (0 = GOMAXPROCS)")
		shards             = flag.Int("shards", 1, "number of corpus shards (1 = no sharding)")
		shard              = flag.Int("shard", 0, "shard index to process (0-based; requires -shards > 1)")
		stream             = flag.Bool("stream", false, "stream per-case results as JSON lines instead of collecting the full report")
		progress           = flag.Bool("progress", false, "print per-case progress lines to stderr")
	)
	flag.Parse()

	if err := run(options{
		Mode:                   *mode,
		CorpusPath:             *corpusPath,
		GovernanceConfigPath:   *governanceConfig,
		GovernanceManifestPath: *governanceManifest,
		GovernanceFormalPath:   *governanceFormal,
		SplitConfigPath:        *splitConfig,
		EvaluationSplit:        *evaluationSplit,
		ExpectedArtifactSHA256: *expectedArtifact,
		MaxRecords:             *maxRecords,
		MaxBytes:               *maxBytes,
		AllowUngoverned:        *allowUngoverned,
		BaseURL:                *baseURL,
		AdminURL:               *adminURL,
		Timeout:                *timeout,
		ToolTimeout:            *toolTimeout,
		Insecure:               *insecure,
		BlockStatuses:          *blockStatuses,
		OutputPath:             *outputPath,
		NucleiTemplates:        *nucleiTemplates,
		RequireExternal:        *requireExternal,
		SkipExternal:           *skipExternal,
		Workers:                *workers,
		Shards:                 *shards,
		Shard:                  *shard,
		Stream:                 *stream,
		Progress:               *progress,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	return runContext(context.Background(), opts)
}

// runWithContext is kept separate from the CLI entry point so callers can
// cancel a governance run without changing the behavior of existing modes.
func runWithContext(ctx context.Context, opts options) error {
	return runContext(ctx, opts)
}

func runContext(ctx context.Context, opts options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ExpectedArtifactSHA256) != "" && opts.Mode != "evaluate-split" {
		return errors.New("--expected-artifact-sha256 is only supported in evaluate-split mode")
	}
	if opts.Mode == "govern" {
		var summary bytes.Buffer
		if err := runGovernanceWithOutput(ctx, opts.GovernanceConfigPath, opts.OutputPath, &summary); err != nil {
			return err
		}
		if opts.OutputPath == "" {
			_, err := os.Stdout.Write(summary.Bytes())
			return err
		}
		return writeAtomicReport(opts.OutputPath, summary.Bytes())
	}
	if opts.Mode == "split" {
		return runEvaluationSplit(ctx, opts)
	}
	if opts.Mode == "evaluate-split" {
		return runEvaluationSplitArtifact(ctx, opts)
	}
	if opts.Mode != "analyzer" && opts.Mode != "http" && opts.Mode != "gate" {
		return fmt.Errorf("unsupported mode %q", opts.Mode)
	}
	if opts.Shards == 0 && !opts.Stream {
		opts.Shards = 1
	}
	if err := security.ValidateShard(opts.Shards, opts.Shard); err != nil {
		return err
	}
	file, err := openLocalRegularFile(opts.CorpusPath, "corpus")
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(strings.ToLower(opts.CorpusPath), ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}

	if opts.Stream {
		return runStream(opts, reader)
	}

	cases := make([]security.Case, 0)
	corpusStats, err := security.ForEachJSONLWithStats(reader, opts.Shards, opts.Shard, func(tc security.Case) error {
		cases = append(cases, tc)
		return nil
	})
	if err != nil {
		return err
	}
	if corpusStats.SkippedOverlong > 0 {
		return fmt.Errorf("corpus contains %d overlong record(s); refusing incomplete evaluation", corpusStats.SkippedOverlong)
	}
	if corpusStats.TotalCases == 0 {
		return errors.New("corpus is empty")
	}
	if corpusStats.SelectedCases == 0 {
		return errors.New("corpus shard is empty")
	}

	started := time.Now().UTC()
	report := summary{
		Mode:      opts.Mode,
		Corpus:    opts.CorpusPath,
		BaseURL:   opts.BaseURL,
		StartedAt: started,
		Results:   make([]result, 0, len(cases)),
	}

	analyzer := semantic.NewAnalyzer("block", 2)

	switch opts.Mode {
	case "analyzer":
		for _, res := range runConcurrent(cases, opts.Workers, func(tc security.Case) result {
			return validateAnalyzer(analyzer, tc)
		}) {
			report.addReport(res, opts.Progress)
		}
	case "http":
		if strings.TrimSpace(opts.BaseURL) == "" {
			return errors.New("--base-url is required in http mode")
		}
		statuses, err := parseBlockStatuses(opts.BlockStatuses)
		if err != nil {
			return err
		}
		client := httpClient(opts.Timeout, opts.Insecure)
		for _, res := range runConcurrent(cases, opts.Workers, func(tc security.Case) result {
			return validateHTTP(client, opts.BaseURL, statuses, tc)
		}) {
			report.addReport(res, opts.Progress)
		}
	case "gate":
		if strings.TrimSpace(opts.BaseURL) == "" {
			return errors.New("--base-url is required in gate mode")
		}
		statuses, err := parseBlockStatuses(opts.BlockStatuses)
		if err != nil {
			return err
		}
		client := httpClient(opts.Timeout, opts.Insecure)
		for _, res := range runConcurrent(cases, opts.Workers, func(tc security.Case) result {
			return validateAnalyzer(analyzer, tc)
		}) {
			report.addReport(res, opts.Progress)
		}
		for _, res := range runConcurrent(cases, opts.Workers, func(tc security.Case) result {
			return validateHTTP(client, opts.BaseURL, statuses, tc)
		}) {
			report.addReport(res, opts.Progress)
		}
		if err := runGateSuites(&report, opts); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported mode %q", opts.Mode)
	}

	report.DurationMS = durationMS(time.Since(started))
	if report.AttackTotal > 0 {
		report.DetectionRate = float64(report.AttackDetected) / float64(report.AttackTotal)
	}
	if report.BenignTotal > 0 {
		report.FalsePositiveRate = float64(report.FalsePositive) / float64(report.BenignTotal)
	}
	sort.Slice(report.Results, func(i, j int) bool {
		return report.Results[i].Name < report.Results[j].Name
	})
	sort.Slice(report.ExternalSuites, func(i, j int) bool {
		return report.ExternalSuites[i].Name < report.ExternalSuites[j].Name
	})

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if opts.OutputPath == "" {
		_, err = os.Stdout.Write(encoded)
	} else {
		err = os.WriteFile(opts.OutputPath, encoded, 0o644)
	}
	if err != nil {
		return err
	}
	if report.Failures > 0 {
		return fmt.Errorf("security corpus validation failed: %d/%d cases failed", report.Failures, report.Total)
	}
	return nil
}

// runEvaluationSplit builds the independent train/validation/blind artifact.
// It intentionally loads the complete input in one process: sharding before
// grouping could split a shared site/session across partitions and invalidate
// the leakage guarantee.
func runEvaluationSplit(ctx context.Context, opts options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Stream {
		return errors.New("--stream is not supported in split mode")
	}
	if opts.Shards < 0 || opts.Shards > 1 || opts.Shard != 0 {
		return errors.New("split mode requires one complete input shard")
	}
	if strings.TrimSpace(opts.CorpusPath) == "" {
		return errors.New("--corpus is required in split mode")
	}
	if isRemotePath(opts.CorpusPath) {
		return errors.New("--corpus must be a local JSONL file in split mode")
	}
	if strings.TrimSpace(opts.SplitConfigPath) == "" {
		return errors.New("--split-config is required in split mode")
	}
	if isRemotePath(opts.SplitConfigPath) {
		return errors.New("--split-config must be a local JSON file")
	}
	manifestPath := strings.TrimSpace(opts.GovernanceManifestPath)
	formalPath := strings.TrimSpace(opts.GovernanceFormalPath)
	if manifestPath != "" && isRemotePath(manifestPath) {
		return errors.New("--governance-manifest must be a local JSON file")
	}
	if formalPath != "" && isRemotePath(formalPath) {
		return errors.New("--governance-formal must be a local JSONL file")
	}
	if strings.TrimSpace(opts.OutputPath) != "" &&
		(sameLocalPath(opts.OutputPath, opts.CorpusPath) || sameLocalPath(opts.OutputPath, opts.SplitConfigPath) ||
			(manifestPath != "" && sameLocalPath(opts.OutputPath, manifestPath)) ||
			(formalPath != "" && sameLocalPath(opts.OutputPath, formalPath))) {
		return errors.New("split output path overlaps an input")
	}
	if manifestPath != "" && (sameLocalPath(manifestPath, opts.CorpusPath) || sameLocalPath(manifestPath, opts.SplitConfigPath)) {
		return errors.New("governance manifest path overlaps an input")
	}
	if formalPath != "" && (sameLocalPath(formalPath, opts.CorpusPath) ||
		sameLocalPath(formalPath, opts.SplitConfigPath) ||
		(manifestPath != "" && sameLocalPath(formalPath, manifestPath))) {
		return errors.New("governance formal path overlaps another input")
	}
	cfg, err := loadEvaluationSplitConfig(opts.SplitConfigPath)
	if err != nil {
		return err
	}
	file, err := openLocalRegularFile(opts.CorpusPath, "evaluation corpus")
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("evaluation corpus must be a regular file")
	}
	var reader io.Reader = file
	var gz *gzip.Reader
	if strings.HasSuffix(strings.ToLower(opts.CorpusPath), ".gz") {
		gz, err = gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open evaluation gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}
	// Hash the decompressed split input independently from the governance formal
	// output. A grouping sidecar can add site/session/time metadata while still
	// being required to match every governed formal row below.
	inputDigest := sha256.New()
	reader = io.TeeReader(reader, inputDigest)
	records, stats, err := security.LoadEvaluationJSONL(reader, security.EvaluationLoadOptions{
		MaxRecords: opts.MaxRecords, MaxBytes: opts.MaxBytes,
		RequireGoverned:            opts.AllowUngoverned == false,
		VerifyGovernanceProvenance: opts.AllowUngoverned,
	})
	if err != nil {
		return err
	}
	if stats.SkippedOverlong > 0 {
		return fmt.Errorf("evaluation corpus contains %d overlong record(s); clean them before splitting", stats.SkippedOverlong)
	}
	if len(records) == 0 {
		return errors.New("evaluation corpus is empty")
	}
	artifact, err := security.BuildEvaluationSplit(records, cfg)
	if err != nil {
		return fmt.Errorf("build evaluation split: %w", err)
	}
	artifact.LoadStats = stats
	if artifact.Governed {
		if manifestPath == "" {
			return errors.New("--governance-manifest is required for governed evaluation splits")
		}
		inputHash := hex.EncodeToString(inputDigest.Sum(nil))
		manifest, binding, err := loadEvaluationGovernanceBinding(manifestPath, inputHash, stats.TotalRecords)
		if err != nil {
			return err
		}
		if err := verifyGovernanceSourceHashes(ctx, manifest); err != nil {
			return err
		}
		if err := verifyGovernedSplitMembership(records, inputHash, formalPath, manifest, opts.MaxRecords, opts.MaxBytes); err != nil {
			return err
		}
		artifact.Governance = &binding
	} else if manifestPath != "" || formalPath != "" {
		return errors.New("governance binding flags cannot be used with an ungoverned evaluation split")
	}
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if strings.TrimSpace(opts.OutputPath) == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return writeAtomicReport(opts.OutputPath, encoded)
}

func loadEvaluationSplitConfig(path string) (security.SplitConfig, error) {
	var cfg security.SplitConfig
	path = strings.TrimSpace(path)
	if path == "" {
		return cfg, errors.New("split config path is required")
	}
	if isRemotePath(path) {
		return cfg, errors.New("split config must be a local JSON file")
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return cfg, fmt.Errorf("open split config: %w", err)
	}
	if !lstat.Mode().IsRegular() {
		return cfg, errors.New("split config must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open split config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return cfg, fmt.Errorf("stat split config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return cfg, errors.New("split config must be a regular file")
	}
	if !os.SameFile(lstat, info) {
		return cfg, errors.New("split config changed while opening")
	}
	const maxSplitConfigBytes = 1 << 20
	if info.Size() > maxSplitConfigBytes {
		return cfg, fmt.Errorf("split config exceeds %d bytes", maxSplitConfigBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSplitConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("read split config: %w", err)
	}
	if len(data) > maxSplitConfigBytes {
		return cfg, fmt.Errorf("split config exceeds %d bytes", maxSplitConfigBytes)
	}
	if err := validateSplitConfigJSON(data); err != nil {
		return cfg, fmt.Errorf("parse split config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse split config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, errors.New("parse split config: multiple JSON values")
		}
		return cfg, fmt.Errorf("parse split config: %w", err)
	}
	return cfg, nil
}

// validateSplitConfigJSON rejects malformed UTF-8 and duplicate object keys
// before encoding/json applies last-value-wins semantics. Split configuration
// is a local trust-boundary input: bounding and validating it keeps a symlinked
// or oversized file from bypassing the deterministic assignment contract.
func validateSplitConfigJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := scanSplitConfigJSONValue(decoder, 0)
	if err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	if duplicate {
		return errors.New("duplicate JSON object key")
	}
	return nil
}

func scanSplitConfigJSONValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > security.DefaultEvaluationArtifactMaxDepth {
		return false, errors.New("split config JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		duplicate := false
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, errors.New("JSON object key is not a string")
			}
			key = strings.ToLower(key)
			if _, exists := seen[key]; exists {
				duplicate = true
			}
			seen[key] = struct{}{}
			childDuplicate, err := scanSplitConfigJSONValue(decoder, depth+1)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	case '[':
		duplicate := false
		for decoder.More() {
			childDuplicate, err := scanSplitConfigJSONValue(decoder, depth+1)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	default:
		return false, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

const maxEvaluationGovernanceManifestBytes = 8 << 20

// loadEvaluationGovernanceBinding verifies the manifest's self-hash and its
// formal output identity before a split can be labelled governed. inputHash is
// the decompressed split input identity; it may differ from the formal output
// when a metadata envelope adds grouping fields.
func loadEvaluationGovernanceBinding(path, inputHash string, formalRecords int) (security.GovernanceManifest, security.EvaluationGovernanceBinding, error) {
	var manifest security.GovernanceManifest
	var binding security.EvaluationGovernanceBinding
	path = strings.TrimSpace(path)
	if path == "" {
		return manifest, binding, errors.New("governance manifest path is required")
	}
	if isRemotePath(path) {
		return manifest, binding, errors.New("governance manifest must be a local JSON file")
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return manifest, binding, fmt.Errorf("open governance manifest: %w", err)
	}
	if !lstat.Mode().IsRegular() {
		return manifest, binding, errors.New("governance manifest must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return manifest, binding, fmt.Errorf("open governance manifest: %w", err)
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return manifest, binding, fmt.Errorf("stat governance manifest: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		return manifest, binding, errors.New("governance manifest must be a regular file")
	}
	if !os.SameFile(lstat, fileInfo) {
		return manifest, binding, errors.New("governance manifest changed while opening")
	}
	if fileInfo.Size() > maxEvaluationGovernanceManifestBytes {
		return manifest, binding, fmt.Errorf("governance manifest exceeds %d bytes", maxEvaluationGovernanceManifestBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEvaluationGovernanceManifestBytes+1))
	if err != nil {
		return manifest, binding, fmt.Errorf("read governance manifest: %w", err)
	}
	if len(data) > maxEvaluationGovernanceManifestBytes {
		return manifest, binding, fmt.Errorf("governance manifest exceeds %d bytes", maxEvaluationGovernanceManifestBytes)
	}
	if err := validateGovernanceManifestJSON(data); err != nil {
		return manifest, binding, fmt.Errorf("parse governance manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, binding, fmt.Errorf("parse governance manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return manifest, binding, errors.New("parse governance manifest: multiple JSON values")
		}
		return manifest, binding, fmt.Errorf("parse governance manifest: %w", err)
	}
	manifestPayloadHash := strings.TrimSpace(manifest.ManifestPayloadHash)
	if !validSHA256Hex(manifestPayloadHash) {
		return manifest, binding, errors.New("governance manifest is missing a valid manifest_payload_hash")
	}
	manifest.ManifestPayloadHash = ""
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, binding, fmt.Errorf("marshal governance manifest payload: %w", err)
	}
	if got := digestHex(payload); got != manifestPayloadHash {
		return manifest, binding, fmt.Errorf("governance manifest payload hash mismatch: got %s want %s", got, manifestPayloadHash)
	}
	manifest.ManifestPayloadHash = manifestPayloadHash
	formalOutputHash := ""
	if manifest.OutputHashes != nil {
		formalOutputHash = strings.TrimSpace(manifest.OutputHashes["formal"])
	}
	if !validSHA256Hex(formalOutputHash) {
		return manifest, binding, errors.New("governance manifest output_hashes.formal is missing or invalid")
	}
	if err := validateGovernanceManifestInputHashes(manifest); err != nil {
		return manifest, binding, err
	}
	if formalRecords > 0 && manifest.Formal != formalRecords {
		return manifest, binding, fmt.Errorf("split input records do not match governance manifest formal count: got %d want %d", formalRecords, manifest.Formal)
	}
	if manifest.Formal < 1 {
		return manifest, binding, errors.New("governance manifest formal count must be positive")
	}
	if manifest.Rejected != 0 {
		return manifest, binding, fmt.Errorf("governance manifest contains %d rejected input rows", manifest.Rejected)
	}
	if manifest.ByDecision == nil {
		return manifest, binding, errors.New("governance manifest by_decision is missing")
	}
	hardReject, ok := manifest.ByDecision["hard_reject"]
	if !ok || hardReject != 0 {
		return manifest, binding, fmt.Errorf("governance manifest hard_reject count must be zero, got %d", hardReject)
	}
	for name, value := range map[string]string{
		"pipeline":    manifest.Pipeline,
		"version":     manifest.Version,
		"policy_hash": manifest.PolicyHash,
		"review_hash": manifest.ReviewHash,
	} {
		if strings.TrimSpace(value) == "" {
			return manifest, binding, fmt.Errorf("governance manifest %s is required", name)
		}
	}
	if !validSHA256Hex(inputHash) {
		return manifest, binding, errors.New("split input hash is invalid")
	}
	binding = security.EvaluationGovernanceBinding{
		ManifestSHA256:      digestHex(data),
		ManifestPayloadHash: manifestPayloadHash,
		FormalSHA256:        formalOutputHash,
		InputSHA256:         inputHash,
		FormalRecords:       manifest.Formal,
		Pipeline:            manifest.Pipeline,
		Version:             manifest.Version,
		PolicyHash:          manifest.PolicyHash,
		ReviewHash:          manifest.ReviewHash,
	}
	if err := security.ValidateEvaluationGovernanceBinding(&binding); err != nil {
		return manifest, security.EvaluationGovernanceBinding{}, err
	}
	return manifest, binding, nil
}

// validateGovernanceManifestInputHashes keeps the source registry and its
// recorded identities closed under the manifest. Optional files that were
// absent during governance are the only declared exception; every other
// source must have one canonical SHA-256 entry, and no undeclared entry may
// be smuggled into the map.
func validateGovernanceManifestInputHashes(manifest security.GovernanceManifest) error {
	if len(manifest.InputHashes) == 0 {
		return errors.New("governance manifest input_hashes must contain at least one source")
	}
	missing := make(map[string]struct{}, len(manifest.MissingOptional))
	for _, path := range manifest.MissingOptional {
		path = strings.TrimSpace(path)
		if path == "" {
			return errors.New("governance manifest missing_optional contains an empty path")
		}
		if _, duplicate := missing[path]; duplicate {
			return fmt.Errorf("governance manifest missing_optional contains duplicate path %q", path)
		}
		missing[path] = struct{}{}
	}
	declared := make(map[string]bool, len(manifest.SourceSpecs))
	expected := make(map[string]struct{}, len(manifest.SourceSpecs))
	// Keep the exact serialized path as the manifest key, but reject filesystem
	// aliases in source_specs. Otherwise `source.jsonl`, `./source.jsonl`, and a
	// symlink to either could be counted as independent sources.
	seenSources := make([]string, 0, len(manifest.SourceSpecs))
	for _, source := range manifest.SourceSpecs {
		path := strings.TrimSpace(source.Path)
		if path == "" {
			return errors.New("governance manifest source_specs contains an empty path")
		}
		for _, previous := range seenSources {
			if sameLocalPath(previous, path) {
				if previous == path {
					return fmt.Errorf("governance manifest source_specs contains duplicate path %q", path)
				}
				return fmt.Errorf("governance manifest source_specs contains duplicate or aliased path %q (same as %q)", path, previous)
			}
		}
		seenSources = append(seenSources, path)
		declared[path] = source.Optional
		if !source.Optional {
			expected[path] = struct{}{}
		} else if _, isMissing := missing[path]; !isMissing {
			expected[path] = struct{}{}
		}
	}
	for path := range missing {
		optional, ok := declared[path]
		if !ok || !optional {
			return fmt.Errorf("governance manifest missing_optional path %q is not a declared optional source", path)
		}
	}
	for path, hash := range manifest.InputHashes {
		if strings.TrimSpace(path) == "" {
			return errors.New("governance manifest input_hashes contains an empty path")
		}
		if hash != strings.TrimSpace(hash) || !validSHA256Hex(hash) {
			return fmt.Errorf("governance manifest input hash for %q is missing or invalid", path)
		}
		if _, ok := expected[path]; !ok {
			return fmt.Errorf("governance manifest input hash for undeclared source %q", path)
		}
	}
	for path := range expected {
		if _, ok := manifest.InputHashes[path]; !ok {
			return fmt.Errorf("governance manifest is missing an input hash for source %q", path)
		}
	}
	return nil
}

// maxGovernanceSourceHashBytes is the largest raw source file that split mode
// will re-hash when binding an input to a governance manifest. Governance uses
// the same ceiling for one source, so this keeps verification finite even when
// a hand-authored manifest advertises an unbounded or otherwise unsafe limit.
const maxGovernanceSourceHashBytes int64 = 8 << 30

// verifyGovernanceSourceHashes closes the gap between a manifest's declared
// input_hashes and the files that are present when a split is created. The
// provenance index intentionally checks only referenced lines; this full-file
// pass also detects an appended or replaced unreferenced line before the split
// can be labelled governed.
func verifyGovernanceSourceHashes(ctx context.Context, manifest security.GovernanceManifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateGovernanceManifestInputHashes(manifest); err != nil {
		return err
	}
	missing := make(map[string]struct{}, len(manifest.MissingOptional))
	for _, path := range manifest.MissingOptional {
		missing[path] = struct{}{}
	}
	maxBytes := maxGovernanceSourceHashBytes
	if manifest.Limits.MaxInputBytes > 0 && manifest.Limits.MaxInputBytes < maxBytes {
		maxBytes = manifest.Limits.MaxInputBytes
	}
	missingPaths := make([]string, 0, len(missing))
	for _, source := range manifest.SourceSpecs {
		path := strings.TrimSpace(source.Path)
		if path == "" {
			return errors.New("governance manifest source_specs contains an empty path")
		}
		if isRemotePath(path) {
			return fmt.Errorf("governance manifest source %q must be a local file", path)
		}
		_, wasMissing := missing[path]
		_, lstatErr := os.Lstat(path)
		if wasMissing {
			if lstatErr == nil {
				return fmt.Errorf("governance optional source %q appeared after the manifest was created", path)
			}
			if errors.Is(lstatErr, os.ErrNotExist) {
				missingPaths = append(missingPaths, path)
				continue
			}
			return fmt.Errorf("inspect governance optional source %q: %w", path, lstatErr)
		}
		expected, ok := manifest.InputHashes[path]
		if !ok {
			return fmt.Errorf("governance manifest is missing an input hash for source %q", path)
		}
		got, err := hashGovernanceSourceFile(ctx, path, maxBytes)
		if err != nil {
			return fmt.Errorf("hash governance source %q: %w", path, err)
		}
		if got != expected {
			return fmt.Errorf("governance source hash mismatch for %q: got %s want %s", path, got, expected)
		}
	}
	// A missing optional file can appear while the required sources are being
	// hashed. Re-check once at the end so an ordinary concurrent writer cannot
	// silently turn an absent optional input into a governed input.
	for _, path := range missingPaths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("governance optional source %q appeared after the manifest was created", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect governance optional source %q: %w", path, err)
		}
	}
	return nil
}

func hashGovernanceSourceFile(ctx context.Context, path string, maxBytes int64) (string, error) {
	if isRemotePath(path) {
		return "", errors.New("governance source must be a local file")
	}
	file, err := openLocalRegularFile(path, "governance source")
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", errors.New("governance source must be a regular file")
	}
	if maxBytes < 1 || maxBytes > maxGovernanceSourceHashBytes {
		maxBytes = maxGovernanceSourceHashBytes
	}
	if before.Size() > maxBytes {
		return "", fmt.Errorf("exceeds %d bytes", maxBytes)
	}
	h := sha256.New()
	buf := make([]byte, 128*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := file.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				return "", fmt.Errorf("exceeds %d bytes", maxBytes)
			}
			if _, err := h.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() ||
		!os.SameFile(before, pathAfter) || before.Size() != pathAfter.Size() {
		return "", errors.New("changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// validateGovernanceManifestJSON rejects duplicate members before
// encoding/json can apply its last-value-wins behavior. The file is already
// byte-bounded by the caller; depth is bounded independently to avoid an
// adversarially nested local manifest exhausting the call stack.
func validateGovernanceManifestJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := scanGovernanceManifestJSONValue(decoder, 0)
	if err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	if duplicate {
		return errors.New("duplicate JSON object key")
	}
	return nil
}

func scanGovernanceManifestJSONValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > security.DefaultEvaluationArtifactMaxDepth {
		return false, errors.New("governance manifest JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		duplicate := false
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, errors.New("JSON object key is not a string")
			}
			key = strings.ToLower(key)
			if _, exists := seen[key]; exists {
				duplicate = true
			}
			seen[key] = struct{}{}
			childDuplicate, err := scanGovernanceManifestJSONValue(decoder, depth+1)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	case '[':
		duplicate := false
		for decoder.More() {
			childDuplicate, err := scanGovernanceManifestJSONValue(decoder, depth+1)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	default:
		return false, nil
	}
}

func verifyGovernedSplitMembership(records []security.EvaluationRecord, inputHash, formalPath string, manifest security.GovernanceManifest, maxRecords int, maxBytes int64) error {
	if err := verifyGovernedSourceReferences(records, manifest); err != nil {
		return err
	}
	formalHash := strings.TrimSpace(manifest.OutputHashes["formal"])
	if inputHash == formalHash {
		// The split input is the exact formal output already checked by the
		// manifest hash and record count. No second file read is necessary.
		return nil
	}
	formalPath = strings.TrimSpace(formalPath)
	if formalPath == "" {
		return errors.New("--governance-formal is required when the split corpus is a metadata envelope rather than the exact formal snapshot")
	}
	formalRecords, stats, loadedHash, err := loadGovernedEvaluationFile(formalPath, maxRecords, maxBytes)
	if err != nil {
		return fmt.Errorf("load governance formal snapshot: %w", err)
	}
	if loadedHash != formalHash {
		return fmt.Errorf("governance formal snapshot hash mismatch: got %s want %s", loadedHash, formalHash)
	}
	if stats.TotalRecords != manifest.Formal || len(formalRecords) != manifest.Formal {
		return fmt.Errorf("governance formal snapshot records do not match manifest: got %d want %d", len(formalRecords), manifest.Formal)
	}
	if len(records) != len(formalRecords) {
		return fmt.Errorf("split input records do not match formal snapshot: got %d want %d", len(records), len(formalRecords))
	}
	byFingerprint := make(map[string]security.EvaluationRecord, len(formalRecords))
	for i, record := range formalRecords {
		fingerprint := strings.ToLower(strings.TrimSpace(record.Fingerprint))
		if _, exists := byFingerprint[fingerprint]; exists {
			return fmt.Errorf("governance formal snapshot contains duplicate fingerprint at record %d", i)
		}
		byFingerprint[fingerprint] = record
	}
	for i, record := range records {
		fingerprint := strings.ToLower(strings.TrimSpace(record.Fingerprint))
		formal, ok := byFingerprint[fingerprint]
		if !ok {
			return fmt.Errorf("split input record %d is absent from the governance formal snapshot", i)
		}
		if !sameGovernedEvaluationIdentity(record, formal) {
			return fmt.Errorf("split input record %d does not preserve its governance formal identity", i)
		}
		delete(byFingerprint, fingerprint)
	}
	if len(byFingerprint) != 0 {
		return fmt.Errorf("split input omits %d governance formal record(s)", len(byFingerprint))
	}
	return nil
}

// verifyGovernedSourceReferences prevents a metadata envelope from pointing
// at an undeclared local file that happens to contain the same request line.
// Matching is filesystem-aware but deliberately case-sensitive on a
// case-sensitive filesystem; EqualFold would conflate two distinct source
// files such as source.jsonl and SOURCE.jsonl on Linux.
func verifyGovernedSourceReferences(records []security.EvaluationRecord, manifest security.GovernanceManifest) error {
	declared := make([]string, 0, len(manifest.SourceSpecs))
	for _, source := range manifest.SourceSpecs {
		path := strings.TrimSpace(source.Path)
		if _, ok := manifest.InputHashes[path]; ok {
			declared = append(declared, path)
		}
	}
	if len(declared) == 0 {
		return errors.New("governance manifest has no present source paths")
	}
	for i, record := range records {
		path := strings.TrimSpace(record.GovernancePath)
		allowed := false
		for _, sourcePath := range declared {
			if sameGovernancePath(path, sourcePath) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("split input record %d governance path %q is not a declared governance source", i, path)
		}
	}
	return nil
}

func loadGovernedEvaluationFile(path string, maxRecords int, maxBytes int64) ([]security.EvaluationRecord, security.EvaluationLoadStats, string, error) {
	var emptyStats security.EvaluationLoadStats
	file, err := openLocalRegularFile(path, "governance formal snapshot")
	if err != nil {
		return nil, emptyStats, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, emptyStats, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, emptyStats, "", errors.New("governance formal snapshot must be a regular file")
	}
	var reader io.Reader = file
	var gz *gzip.Reader
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err = gzip.NewReader(file)
		if err != nil {
			return nil, emptyStats, "", err
		}
		defer gz.Close()
		reader = gz
	}
	digest := sha256.New()
	records, stats, err := security.LoadEvaluationJSONL(io.TeeReader(reader, digest), security.EvaluationLoadOptions{
		MaxRecords:      maxRecords,
		MaxBytes:        maxBytes,
		RequireGoverned: true,
	})
	if err != nil {
		return nil, stats, "", err
	}
	if stats.SkippedOverlong != 0 {
		return nil, stats, "", fmt.Errorf("contains %d overlong record(s)", stats.SkippedOverlong)
	}
	return records, stats, hex.EncodeToString(digest.Sum(nil)), nil
}

// openLocalRegularFile rejects final-component symlinks and closes the small
// Lstat/Open race before any caller starts hashing or parsing an evidence
// artifact.  A content hash alone is not enough here: following a mutable
// indirection could pair a valid manifest with a different file on a later
// replay.
func openLocalRegularFile(path, label string) (*os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%s path is required", label)
	}
	if isRemotePath(path) {
		return nil, fmt.Errorf("%s must be a local file", label)
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	if !lstat.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	if !os.SameFile(lstat, info) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed while opening", label)
	}
	return file, nil
}

func sameGovernedEvaluationIdentity(input, formal security.EvaluationRecord) bool {
	if !strings.EqualFold(strings.TrimSpace(input.Fingerprint), strings.TrimSpace(formal.Fingerprint)) ||
		strings.TrimSpace(input.Source) != strings.TrimSpace(formal.Source) ||
		input.GovernanceLine != formal.GovernanceLine ||
		!strings.EqualFold(strings.TrimSpace(input.RawHash), strings.TrimSpace(formal.RawHash)) ||
		!strings.EqualFold(strings.TrimSpace(input.Decision), strings.TrimSpace(formal.Decision)) ||
		strings.TrimSpace(input.ReviewRuleVersion) != strings.TrimSpace(formal.ReviewRuleVersion) ||
		strings.TrimSpace(input.Reviewer) != strings.TrimSpace(formal.Reviewer) ||
		strings.TrimSpace(input.ReviewReason) != strings.TrimSpace(formal.ReviewReason) ||
		strings.TrimSpace(input.ReviewedAt) != strings.TrimSpace(formal.ReviewedAt) {
		return false
	}
	if !sameGovernancePath(input.GovernancePath, formal.GovernancePath) {
		return false
	}
	return strings.TrimSpace(input.Case.Name) == strings.TrimSpace(formal.Case.Name) &&
		strings.TrimSpace(input.Case.SourceFamily) == strings.TrimSpace(formal.Case.SourceFamily) &&
		strings.EqualFold(strings.TrimSpace(input.Case.Label), strings.TrimSpace(formal.Case.Label)) &&
		strings.EqualFold(strings.TrimSpace(input.Case.Category), strings.TrimSpace(formal.Case.Category)) &&
		strings.TrimSpace(input.Case.Rationale) == strings.TrimSpace(formal.Case.Rationale)
}

func sameGovernancePath(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	canonicalA := canonicalPath(a)
	canonicalB := canonicalPath(b)
	if canonicalA == canonicalB {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

func verifyEvaluationGovernanceBinding(path string, expected *security.EvaluationGovernanceBinding) error {
	if expected == nil {
		return errors.New("governance binding is missing")
	}
	if err := security.ValidateEvaluationGovernanceBinding(expected); err != nil {
		return err
	}
	// The locked split artifact is the trust anchor for InputSHA256. Replay does
	// not re-open the original split input; it re-verifies every manifest-derived
	// field and preserves the input hash as an audit identity protected by the
	// artifact's immutable storage and externally recorded artifact hash.
	_, actual, err := loadEvaluationGovernanceBinding(path, expected.InputSHA256, expected.FormalRecords)
	if err != nil {
		return err
	}
	if actual != *expected {
		return errors.New("governance manifest does not match the split artifact binding")
	}
	return nil
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validSHA256Hex(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// runEvaluationSplitArtifact replays exactly one partition from a validated
// split artifact. It is deliberately separate from raw analyzer mode so a
// caller cannot accidentally treat an unassigned corpus as a blind result.
func runEvaluationSplitArtifact(ctx context.Context, opts options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Stream {
		return errors.New("--stream is not supported in evaluate-split mode")
	}
	if opts.Shards < 0 || opts.Shards > 1 || opts.Shard != 0 {
		return errors.New("evaluate-split mode requires one complete artifact")
	}
	if strings.TrimSpace(opts.CorpusPath) == "" {
		return errors.New("--corpus is required in evaluate-split mode and must point to a split artifact")
	}
	if isRemotePath(opts.CorpusPath) {
		return errors.New("split artifact must be a local JSON file")
	}
	if strings.TrimSpace(opts.GovernanceFormalPath) != "" {
		return errors.New("--governance-formal is only supported in split mode")
	}
	manifestPath := strings.TrimSpace(opts.GovernanceManifestPath)
	if manifestPath != "" && isRemotePath(manifestPath) {
		return errors.New("--governance-manifest must be a local JSON file")
	}
	selected, err := parseEvaluationSplit(opts.EvaluationSplit)
	if err != nil {
		return err
	}
	if strings.TrimSpace(opts.OutputPath) != "" && (sameLocalPath(opts.OutputPath, opts.CorpusPath) ||
		(manifestPath != "" && sameLocalPath(opts.OutputPath, manifestPath))) {
		return errors.New("evaluation output path overlaps the split artifact")
	}
	if manifestPath != "" && sameLocalPath(manifestPath, opts.CorpusPath) {
		return errors.New("governance manifest path overlaps the split artifact")
	}
	file, err := openLocalRegularFile(opts.CorpusPath, "evaluation split artifact")
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("split artifact must be a regular file")
	}
	digest := sha256.New()
	artifact, err := security.LoadEvaluationSplitArtifact(io.TeeReader(file, digest), opts.MaxRecords)
	if err != nil {
		return err
	}
	if err := requireCompleteEvaluationLoadStats(artifact.LoadStats, artifact.InputRecords); err != nil {
		return err
	}
	if artifact.Summary.Count(selected) == 0 {
		return fmt.Errorf("evaluation split %q is empty", selected)
	}
	gateRequested := false
	if _, ok := os.LookupEnv("FPR_GATE"); ok {
		gateRequested = true
	}
	if _, ok := os.LookupEnv("TPR_GATE"); ok {
		gateRequested = true
	}
	if artifact.Governed {
		if artifact.Governance == nil {
			return errors.New("governed evaluation split artifact is missing its governance binding")
		}
		if manifestPath == "" {
			return errors.New("--governance-manifest is required when replaying a governed split artifact")
		}
		if err := verifyEvaluationGovernanceBinding(manifestPath, artifact.Governance); err != nil {
			return fmt.Errorf("verify governance manifest: %w", err)
		}
	} else {
		if selected == security.SplitBlind || gateRequested {
			return errors.New("ungoverned evaluation split artifacts cannot be replayed as blind quality evidence")
		}
		if manifestPath != "" {
			return errors.New("--governance-manifest cannot be used with an ungoverned split artifact")
		}
	}
	actualArtifactSHA256 := hex.EncodeToString(digest.Sum(nil))
	expectedArtifactSHA256 := strings.TrimSpace(opts.ExpectedArtifactSHA256)
	if expectedArtifactSHA256 == "" {
		if artifact.Governed || gateRequested {
			return errors.New("--expected-artifact-sha256 is required for governed replay and quality gates")
		}
	} else {
		if !validSHA256Hex(expectedArtifactSHA256) {
			return errors.New("--expected-artifact-sha256 must be a 64-character lowercase SHA-256")
		}
		if expectedArtifactSHA256 != actualArtifactSHA256 {
			return fmt.Errorf("split artifact SHA-256 mismatch: got %s want %s", actualArtifactSHA256, expectedArtifactSHA256)
		}
	}

	rows := make([]security.AssignedEvaluationRecord, 0, artifact.Summary.Count(selected))
	cases := make([]security.Case, 0, artifact.Summary.Count(selected))
	for _, row := range artifact.Records {
		if row.Split != selected {
			continue
		}
		rows = append(rows, row)
		cases = append(cases, row.Case)
	}
	if len(rows) == 0 {
		return fmt.Errorf("evaluation split %q is empty", selected)
	}
	started := time.Now().UTC()
	analyzer := semantic.NewAnalyzer("block", 2)
	results, err := runConcurrentContext(ctx, cases, opts.Workers, func(tc security.Case) result {
		return validateAnalyzerContext(ctx, analyzer, tc)
	})
	if err != nil {
		return err
	}
	for _, item := range results {
		if item.Error != "" {
			return fmt.Errorf("evaluation case %q failed: %s", item.Name, item.Error)
		}
		if item.Warning {
			return fmt.Errorf("evaluation case %q produced a warning: %s", item.Name, item.Error)
		}
	}
	report := buildSplitEvaluationReport(artifact, opts.CorpusPath, digest, selected, rows, results, started)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if strings.TrimSpace(opts.OutputPath) == "" {
		if _, err := os.Stdout.Write(encoded); err != nil {
			return err
		}
	} else if err := writeAtomicReport(opts.OutputPath, encoded); err != nil {
		return err
	}
	if err := applySplitEvaluationGates(report); err != nil {
		return err
	}
	return nil
}

func parseEvaluationSplit(raw string) (security.EvaluationSplit, error) {
	switch security.EvaluationSplit(strings.ToLower(strings.TrimSpace(raw))) {
	case security.SplitTrain:
		return security.SplitTrain, nil
	case security.SplitValidation:
		return security.SplitValidation, nil
	case security.SplitBlind:
		return security.SplitBlind, nil
	default:
		return "", errors.New("--evaluation-split must be one of train, validation, or blind")
	}
}

func requireCompleteEvaluationLoadStats(stats security.EvaluationLoadStats, input int) error {
	if input < 1 {
		return errors.New("evaluation split artifact has no input records")
	}
	if stats.TotalRecords != input || stats.SelectedRecords != input || stats.NonEmptyLines < input || stats.SkippedOverlong != 0 {
		return fmt.Errorf("split artifact load_stats are incomplete or unsafe: %+v", stats)
	}
	return nil
}

func buildSplitEvaluationReport(artifact security.EvaluationSplitArtifact, artifactPath string, digest hash.Hash, selected security.EvaluationSplit, rows []security.AssignedEvaluationRecord, results []result, started time.Time) *splitEvaluationReport {
	selectedGroups := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		selectedGroups[row.Group] = struct{}{}
	}
	report := &splitEvaluationReport{
		Version:          "split-evaluation-v1",
		Mode:             "evaluate-split",
		Artifact:         artifactPath,
		ArtifactSHA256:   hex.EncodeToString(digest.Sum(nil)),
		Split:            selected,
		StartedAt:        started,
		InputRecords:     artifact.InputRecords,
		EvaluatedRecords: len(rows),
		Groups:           len(selectedGroups),
		Repaired:         artifact.Summary.Repaired,
		Sources:          make(map[string]splitSourceMetrics),
		Categories:       make(map[string]splitCategoryMetrics),
		Results:          append([]result(nil), results...),
	}
	if artifact.Governance != nil {
		report.ManifestSHA256 = artifact.Governance.ManifestSHA256
		report.ManifestPayloadHash = artifact.Governance.ManifestPayloadHash
		report.FormalSHA256 = artifact.Governance.FormalSHA256
		report.SplitInputSHA256 = artifact.Governance.InputSHA256
	}
	for i, row := range rows {
		if i >= len(results) {
			break
		}
		item := results[i]
		source := strings.TrimSpace(row.Source)
		src := report.Sources[source]
		if row.Case.Label == "benign" {
			report.BenignTotal++
			src.BenignTotal++
			if item.Detected {
				report.FalsePositive++
				src.BenignFP++
			} else {
				report.BenignClean++
			}
		} else if row.Case.Label == "attack" {
			report.AttackTotal++
			src.AttackTotal++
			if item.Detected {
				report.AttackDetected++
				src.AttackDetected++
			} else {
				report.AttackMissed++
			}
			category := strings.TrimSpace(row.Case.Category)
			if category != "" {
				cat := report.Categories[category]
				cat.AttackTotal++
				if item.Detected {
					cat.AttackDetected++
				}
				report.Categories[category] = cat
			}
			if item.Detected && !item.Passed {
				report.CategoryMismatches++
			}
		}
		report.Sources[source] = src
	}
	report.Failures = report.FalsePositive + report.AttackMissed + report.CategoryMismatches
	if report.BenignTotal > 0 {
		report.FPRPercent = float64(report.FalsePositive) / float64(report.BenignTotal) * 100
		if _, upper, ok := security.WilsonInterval99(report.FalsePositive, report.BenignTotal); ok {
			report.FPRUpper99Percent = upper * 100
		}
	}
	if report.AttackTotal > 0 {
		report.TPRPercent = float64(report.AttackDetected) / float64(report.AttackTotal) * 100
		if lower, _, ok := security.WilsonInterval99(report.AttackDetected, report.AttackTotal); ok {
			report.TPRLower99Percent = lower * 100
		}
	}
	positives := report.AttackDetected + report.FalsePositive
	if positives > 0 {
		report.PrecisionPercent = float64(report.AttackDetected) / float64(positives) * 100
	}
	if report.PrecisionPercent > 0 && report.TPRPercent > 0 {
		report.F1Score = 2 * report.PrecisionPercent * report.TPRPercent / (report.PrecisionPercent + report.TPRPercent)
	}
	for source, metrics := range report.Sources {
		if metrics.BenignTotal > 0 {
			metrics.FPRPercent = float64(metrics.BenignFP) / float64(metrics.BenignTotal) * 100
		}
		if metrics.AttackTotal > 0 {
			metrics.TPRPercent = float64(metrics.AttackDetected) / float64(metrics.AttackTotal) * 100
		}
		report.Sources[source] = metrics
	}
	for category, metrics := range report.Categories {
		if metrics.AttackTotal > 0 {
			metrics.TPRPercent = float64(metrics.AttackDetected) / float64(metrics.AttackTotal) * 100
		}
		report.Categories[category] = metrics
	}
	report.DurationMS = durationMS(time.Since(started))
	sort.Slice(report.Results, func(i, j int) bool { return report.Results[i].Name < report.Results[j].Name })
	return report
}

func applySplitEvaluationGates(report *splitEvaluationReport) error {
	if report == nil {
		return errors.New("split evaluation report is nil")
	}
	fprGateEnabled := false
	tprGateEnabled := false
	if raw, ok := os.LookupEnv("FPR_GATE"); ok {
		fprGateEnabled = true
		gate, err := parseSplitPercentGate("FPR_GATE", raw)
		if err != nil {
			return err
		}
		minimum, err := splitPositiveEnvInt("FPR_MIN_BENIGN", 100)
		if err != nil {
			return err
		}
		if report.BenignTotal < minimum {
			return fmt.Errorf("FPR gate requires at least %d benign samples, got %d", minimum, report.BenignTotal)
		}
		if report.FPRPercent >= gate {
			return fmt.Errorf("%s FPR gate failed: %.4f%% is not below %.4f%%", report.Split, report.FPRPercent, gate)
		}
	}
	if raw, ok := os.LookupEnv("TPR_GATE"); ok {
		tprGateEnabled = true
		gate, err := parseSplitPercentGate("TPR_GATE", raw)
		if err != nil {
			return err
		}
		minimum, err := splitPositiveEnvInt("TPR_MIN_ATTACK", 100)
		if err != nil {
			return err
		}
		if report.AttackTotal < minimum {
			return fmt.Errorf("TPR gate requires at least %d attack samples, got %d", minimum, report.AttackTotal)
		}
		if report.TPRPercent < gate {
			return fmt.Errorf("%s TPR gate failed: %.4f%% < %.4f%%", report.Split, report.TPRPercent, gate)
		}
	}
	// A blind point estimate with one class or one connected group is not an
	// independent quality result. Keep tiny smoke fixtures usable when no gate
	// is requested, but fail closed as soon as a caller asks this command to
	// certify FPR/TPR. The minimum can be raised explicitly for a publication
	// run; it is deliberately not inferred from the requested fractions.
	if report.Split == security.SplitBlind && (fprGateEnabled || tprGateEnabled) {
		if report.BenignTotal < 1 || report.AttackTotal < 1 {
			return fmt.Errorf("blind quality gate requires both benign and attack samples, got benign=%d attack=%d", report.BenignTotal, report.AttackTotal)
		}
		minimumGroups, err := splitPositiveEnvInt("BLIND_MIN_GROUPS", 2)
		if err != nil {
			return err
		}
		if report.Groups < minimumGroups {
			return fmt.Errorf("blind quality gate requires at least %d independent groups, got %d", minimumGroups, report.Groups)
		}
	}
	return nil
}

func parseSplitPercentGate(name, raw string) (float64, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
		return 0, fmt.Errorf("%s must be a finite percentage in [0, 100], got %q", name, raw)
	}
	return value, nil
}

func splitPositiveEnvInt(name string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", name, raw)
	}
	return value, nil
}

func runGovernance(ctx context.Context, configPath string, out io.Writer) error {
	return runGovernanceWithOutput(ctx, configPath, "", out)
}

func runGovernanceWithOutput(ctx context.Context, configPath, summaryPath string, out io.Writer) error {
	if strings.TrimSpace(configPath) == "" {
		return errors.New("--governance-config is required in govern mode")
	}
	if isRemotePath(configPath) {
		return errors.New("--governance-config must be a local JSON file")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg, err := loadGovernanceConfig(configPath)
	if err != nil {
		return err
	}
	if len(cfg.Sources)+len(cfg.Existing)+len(cfg.Incoming) == 0 {
		return errors.New("governance config requires at least one source")
	}
	if err := validateGovernanceConfigPaths(cfg, configPath); err != nil {
		return err
	}
	if err := validateGovernanceSummaryPath(cfg, configPath, summaryPath); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	report, err := security.RunGovernance(ctx, cfg)
	if err != nil {
		return err
	}
	// Duplicate relations are retained in the manifest file for auditability,
	// but omitting the potentially large relation list from stdout keeps CI and
	// local command output bounded and readable.
	manifestSummary := report.Manifest
	manifestSummary.DuplicateRelations = nil
	encoded, err := json.MarshalIndent(manifestSummary, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, err = out.Write(encoded)
	return err
}

func validateGovernanceConfigPaths(cfg security.GovernanceConfig, configPath string) error {
	if strings.TrimSpace(cfg.ReviewPath) != "" {
		for _, source := range append(append(append([]security.SourceSpec{}, cfg.Sources...), cfg.Existing...), cfg.Incoming...) {
			if strings.TrimSpace(source.Path) == "" {
				continue
			}
			if sameLocalPath(cfg.ReviewPath, source.Path) {
				return fmt.Errorf("governance review path overlaps source input: %s", cfg.ReviewPath)
			}
		}
	}
	for _, output := range []string{cfg.FormalPath, cfg.QuarantinePath, cfg.ManifestPath} {
		if strings.TrimSpace(output) == "" {
			continue
		}
		if sameLocalPath(configPath, output) {
			return fmt.Errorf("governance output path overlaps config input: %s", output)
		}
	}
	return nil
}

// validateGovernanceSummaryPath prevents the human-readable summary from
// overwriting a governance input or one of the immutable audit artifacts. The
// core validates its own three outputs; this check covers the CLI-only fourth
// output, including symlink aliases and the config file itself.
func validateGovernanceSummaryPath(cfg security.GovernanceConfig, configPath, summaryPath string) error {
	if strings.TrimSpace(summaryPath) == "" {
		return nil
	}
	if isRemotePath(summaryPath) {
		return errors.New("governance summary path must be a local file")
	}
	protected := []string{configPath, cfg.FormalPath, cfg.QuarantinePath, cfg.ManifestPath, cfg.ReviewPath}
	for _, src := range append(append(append([]security.SourceSpec{}, cfg.Sources...), cfg.Existing...), cfg.Incoming...) {
		protected = append(protected, src.Path)
	}
	for _, path := range protected {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if sameLocalPath(summaryPath, path) {
			return fmt.Errorf("governance summary path overlaps protected input/output: %s", summaryPath)
		}
	}
	return nil
}

func sameLocalPath(a, b string) bool {
	canonicalA := canonicalPath(a)
	canonicalB := canonicalPath(b)
	if canonicalA == canonicalB || strings.EqualFold(canonicalA, canonicalB) {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

func canonicalPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	// The summary normally does not exist yet. Resolve an existing parent so a
	// symlinked output directory cannot bypass the overlap check.
	parent, base := filepath.Dir(abs), filepath.Base(abs)
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Clean(filepath.Join(resolved, base))
	}
	return abs
}

func writeAtomicReport(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".corpus-report-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

const maxGovernanceConfigBytes = 8 << 20

func loadGovernanceConfig(path string) (security.GovernanceConfig, error) {
	var cfg security.GovernanceConfig
	if isRemotePath(path) {
		return cfg, errors.New("governance config must be a local JSON file")
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		return cfg, fmt.Errorf("open governance config: %w", err)
	}
	if !lstat.Mode().IsRegular() {
		return cfg, errors.New("governance config must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open governance config: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return cfg, fmt.Errorf("stat governance config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return cfg, errors.New("governance config must be a regular file")
	}
	if !os.SameFile(lstat, info) {
		return cfg, errors.New("governance config changed while opening")
	}
	if info.Size() > maxGovernanceConfigBytes {
		return cfg, fmt.Errorf("governance config exceeds %d bytes", maxGovernanceConfigBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxGovernanceConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("read governance config: %w", err)
	}
	if len(data) > maxGovernanceConfigBytes {
		return cfg, fmt.Errorf("governance config exceeds %d bytes", maxGovernanceConfigBytes)
	}
	if err := validateGovernanceConfigJSON(data); err != nil {
		return cfg, fmt.Errorf("parse governance config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse governance config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, errors.New("parse governance config: multiple JSON values")
		}
		return cfg, fmt.Errorf("parse governance config: %w", err)
	}
	after, err := f.Stat()
	if err != nil {
		return cfg, fmt.Errorf("stat governance config: %w", err)
	}
	pathAfter, err := os.Stat(path)
	if err != nil {
		return cfg, fmt.Errorf("stat governance config: %w", err)
	}
	if !os.SameFile(info, after) || info.Size() != after.Size() ||
		!os.SameFile(lstat, pathAfter) || lstat.Size() != pathAfter.Size() {
		return cfg, errors.New("governance config changed while reading")
	}
	return cfg, nil
}

// validateGovernanceConfigJSON rejects duplicate members before
// encoding/json applies last-value-wins semantics. Governance configuration
// controls source selection, output paths, limits, and review policy, so an
// ambiguous local file must fail closed just like a split or manifest input.
func validateGovernanceConfigJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := scanGovernanceConfigJSONValue(decoder, 0)
	if err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	if duplicate {
		return errors.New("duplicate JSON object key")
	}
	return nil
}

func scanGovernanceConfigJSONValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > security.DefaultEvaluationArtifactMaxDepth {
		return false, errors.New("governance config JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		duplicate := false
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, errors.New("governance config JSON object key is not a string")
			}
			key = strings.ToLower(key)
			if _, exists := seen[key]; exists {
				duplicate = true
			}
			seen[key] = struct{}{}
			childDuplicate, err := scanGovernanceConfigJSONValue(decoder, depth+1)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	case '[':
		duplicate := false
		for decoder.More() {
			childDuplicate, err := scanGovernanceConfigJSONValue(decoder, depth+1)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	default:
		return false, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func isRemotePath(path string) bool {
	trimmed := strings.TrimSpace(path)
	return strings.Contains(trimmed, "://") || strings.HasPrefix(strings.ToLower(trimmed), "file:")
}

func runStream(opts options, reader io.Reader) error {
	switch opts.Mode {
	case "analyzer", "http", "gate":
	default:
		return fmt.Errorf("unsupported mode %q", opts.Mode)
	}
	if err := validateStreamShardOptions(opts.Shards, opts.Shard); err != nil {
		return err
	}
	if (opts.Mode == "http" || opts.Mode == "gate") && strings.TrimSpace(opts.BaseURL) == "" {
		return errors.New("--base-url is required in http and gate modes")
	}

	started := time.Now().UTC()
	report := summary{
		Mode:      opts.Mode,
		Corpus:    opts.CorpusPath,
		BaseURL:   opts.BaseURL,
		StartedAt: started,
		Results:   make([]result, 0),
	}

	analyzer := semantic.NewAnalyzer("block", 2)
	var client *http.Client
	var statuses map[int]struct{}
	if opts.Mode == "http" || opts.Mode == "gate" {
		var err error
		statuses, err = parseBlockStatuses(opts.BlockStatuses)
		if err != nil {
			return err
		}
		client = httpClient(opts.Timeout, opts.Insecure)
	}

	process := func(tc security.Case) []result {
		switch opts.Mode {
		case "analyzer":
			return []result{validateAnalyzer(analyzer, tc)}
		case "http":
			return []result{validateHTTP(client, opts.BaseURL, statuses, tc)}
		case "gate":
			return []result{validateAnalyzer(analyzer, tc), validateHTTP(client, opts.BaseURL, statuses, tc)}
		default:
			return []result{}
		}
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}

	var out io.Writer = os.Stdout
	var outFile *os.File
	if opts.OutputPath != "" {
		f, err := os.Create(opts.OutputPath)
		if err != nil {
			return err
		}
		outFile = f
		out = f
		defer func() {
			if outFile != nil {
				_ = outFile.Close()
			}
		}()
	}

	cases := make(chan security.Case, workers*2)
	results := make(chan result, workers*2)
	var workersWG sync.WaitGroup
	for w := 0; w < workers; w++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for tc := range cases {
				for _, res := range process(tc) {
					results <- res
				}
			}
		}()
	}

	type corpusLoadResult struct {
		stats security.JSONLStats
		err   error
	}
	loadResult := make(chan corpusLoadResult, 1)
	go func() {
		stats, err := security.ForEachJSONLWithStats(reader, opts.Shards, opts.Shard, func(tc security.Case) error {
			cases <- tc
			return nil
		})
		close(cases)
		loadResult <- corpusLoadResult{stats: stats, err: err}
	}()

	writerDone := make(chan error, 1)
	go func() {
		writerDone <- writeStreamResults(opts, out, results, &report)
	}()

	loaded := <-loadResult
	workersWG.Wait()
	close(results)
	if err := <-writerDone; err != nil {
		return err
	}
	if loaded.err != nil {
		return loaded.err
	}
	if loaded.stats.SkippedOverlong > 0 {
		return fmt.Errorf("corpus contains %d overlong record(s); refusing incomplete evaluation", loaded.stats.SkippedOverlong)
	}
	if loaded.stats.TotalCases == 0 {
		return errors.New("corpus is empty")
	}
	if loaded.stats.SelectedCases == 0 {
		return errors.New("corpus shard is empty")
	}

	if opts.Mode == "gate" {
		if err := runGateSuites(&report, opts); err != nil {
			return err
		}
	}

	report.DurationMS = durationMS(time.Since(started))
	if report.AttackTotal > 0 {
		report.DetectionRate = float64(report.AttackDetected) / float64(report.AttackTotal)
	}
	if report.BenignTotal > 0 {
		report.FalsePositiveRate = float64(report.FalsePositive) / float64(report.BenignTotal)
	}
	sort.Slice(report.ExternalSuites, func(i, j int) bool {
		return report.ExternalSuites[i].Name < report.ExternalSuites[j].Name
	})

	if err := writeStreamSummary(opts, &report); err != nil {
		return err
	}
	if report.Failures > 0 {
		return fmt.Errorf("security corpus validation failed: %d/%d cases failed", report.Failures, report.Total)
	}
	return nil
}

func validateStreamShardOptions(shards, shard int) error {
	return security.ValidateShard(shards, shard)
}

func writeStreamResults(opts options, out io.Writer, results <-chan result, report *summary) error {
	seq := 0
	var writeErr error
	for res := range results {
		seq++
		report.count(res)
		if opts.Progress {
			fmt.Fprintf(os.Stderr, "[progress] %d %s (%s) passed=%t detected=%t\n", seq, res.Name, res.Label, res.Passed, res.Detected)
		}
		if writeErr != nil {
			continue
		}
		encoded, err := json.Marshal(res)
		if err != nil {
			writeErr = err
			continue
		}
		encoded = append(encoded, '\n')
		if _, err := out.Write(encoded); err != nil {
			writeErr = err
		}
	}
	return writeErr
}

func writeStreamSummary(opts options, report *summary) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if opts.OutputPath == "" {
		_, err = os.Stderr.Write(encoded)
		return err
	}
	return os.WriteFile(opts.OutputPath+".summary.json", encoded, 0o644)
}

func runConcurrent(cases []security.Case, workers int, fn func(security.Case) result) []result {
	if len(cases) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > len(cases) {
		workers = len(cases)
	}
	out := make([]result, len(cases))
	if workers <= 1 {
		for i, tc := range cases {
			out[i] = fn(tc)
		}
		return out
	}
	idx := make(chan int, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				out[i] = fn(cases[i])
			}
		}()
	}
	for i := range cases {
		idx <- i
	}
	close(idx)
	wg.Wait()
	return out
}

// runConcurrentContext is the cancellation-aware variant used by independent
// evaluation. Results retain input order so reports remain reproducible even
// when detector work completes out of order.
func runConcurrentContext(ctx context.Context, cases []security.Case, workers int, fn func(security.Case) result) ([]result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(cases) == 0 {
		return nil, nil
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(cases) {
		workers = len(cases)
	}
	out := make([]result, len(cases))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					out[index] = fn(cases[index])
				}
			}
		}()
	}
	dispatching := true
	for index := range cases {
		select {
		case jobs <- index:
		case <-ctx.Done():
			dispatching = false
		}
		if !dispatching {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func validateAnalyzer(analyzer *semantic.Analyzer, tc security.Case) result {
	return validateAnalyzerContext(context.Background(), analyzer, tc)
}

func validateAnalyzerContext(ctx context.Context, analyzer *semantic.Analyzer, tc security.Case) result {
	res := baseResult("analyzer", tc)
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}

	req, err := newCorpusRequest(tc)
	if err != nil {
		res.Error = err.Error()
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	reqCtx, err := engine.NewRequestContext(req, "corpus")
	if err != nil {
		res.Error = err.Error()
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	// The offline runner replays the authority captured with the case. This is
	// an evaluation-only trust boundary; production requests are marked by the
	// proxy only after tenant host validation.
	reqCtx.HostValidated = true
	detection, err := analyzer.Detect(ctx, reqCtx)
	if err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	if detection != nil && detection.Detected {
		res.Detected = true
		res.DetectorCategory = detection.Category
		res.DetectorID = detection.DetectorID
		res.Message = detection.Message
	}
	switch tc.Label {
	case "attack":
		if security.StrictCategory(tc.SourceFamily) {
			res.Passed = res.Detected && res.DetectorCategory == tc.Category
		} else {
			res.Passed = res.Detected
		}
	case "benign":
		res.Passed = !res.Detected
	}
	res.LatencyMS = durationMS(time.Since(start))
	return res
}

func validateHTTP(client *http.Client, baseURL string, blockStatuses map[int]struct{}, tc security.Case) result {
	res := baseResult("http", tc)
	start := time.Now()

	if _, err := parseBaseURL(baseURL); err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	target, err := resolveTarget(baseURL, tc.Target)
	if err != nil {
		res.Error = err.Error()
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	req, err := http.NewRequest(tc.Method, target, strings.NewReader(tc.Body))
	if err != nil {
		res.Error = err.Error()
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	req.Header.Set("User-Agent", "CheeseWAF-Corpus-Runner/0.1")
	applyCorpusHeaders(req, tc.Header)
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	defer netguard.DrainAndClose(resp.Body)
	res.StatusCode = resp.StatusCode
	_, res.Blocked = blockStatuses[resp.StatusCode]
	switch tc.Label {
	case "attack":
		res.Passed = res.Blocked
	case "benign":
		res.Passed = !res.Blocked
	}
	res.LatencyMS = durationMS(time.Since(start))
	return res
}

func baseResult(mode string, tc security.Case) result {
	return result{
		Name:         tc.Name,
		SourceFamily: tc.SourceFamily,
		Label:        tc.Label,
		Category:     tc.Category,
		Rationale:    tc.Rationale,
		Mode:         mode,
		Method:       tc.Method,
		Target:       tc.Target,
	}
}

func newCorpusRequest(tc security.Case) (*http.Request, error) {
	req, err := http.NewRequest(tc.Method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		return nil, err
	}
	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	applyCorpusHeaders(req, tc.Header)
	return req, nil
}

// applyCorpusHeaders mirrors net/http's request model: Host is stored on
// Request.Host rather than in Request.Header. Keeping that distinction makes
// analyzer and live HTTP replays observe the same authority and therefore the
// same same-origin/security semantics as production traffic.
func applyCorpusHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		if strings.EqualFold(strings.TrimSpace(key), "host") {
			req.Host = strings.TrimSpace(value)
			continue
		}
		req.Header.Set(key, value)
	}
}

func parseBlockStatuses(raw string) (map[int]struct{}, error) {
	out := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		status, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid block status %q: %w", part, err)
		}
		if status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid block status %d", status)
		}
		out[status] = struct{}{}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one block status is required")
	}
	return out, nil
}

func httpClient(timeout time.Duration, insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit CLI flag for self-signed test deployments.
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func resolveTarget(baseURL, target string) (string, error) {
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsedTarget.IsAbs() {
		return parsedTarget.String(), nil
	}
	return base.ResolveReference(parsedTarget).String(), nil
}

func parseBaseURL(baseURL string) (*url.URL, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("base URL %q must include scheme and host", baseURL)
	}
	return base, nil
}

func (s *summary) count(res result) {
	s.Total++
	if res.Warning {
		s.Warnings++
		// A warning means the case could not be evaluated (for example, the
		// request could not be constructed). Preserve its label denominator,
		// but never treat it as a pass or as a detected false positive.
		s.Failures++
		switch res.Label {
		case "attack":
			s.AttackTotal++
			s.AttackMissed++
		case "benign":
			s.BenignTotal++
		}
		return
	}
	switch res.Label {
	case "attack":
		s.AttackTotal++
		if res.Passed {
			s.AttackDetected++
		} else {
			s.AttackMissed++
			s.Failures++
		}
	case "benign":
		s.BenignTotal++
		if res.Passed {
			s.BenignClean++
		} else {
			s.FalsePositive++
			s.Failures++
		}
	default:
		s.Failures++
	}
}

func (s *summary) add(res result) {
	s.Results = append(s.Results, res)
	s.count(res)
}

func (s *summary) addReport(res result, progress bool) {
	s.add(res)
	if progress {
		fmt.Fprintf(os.Stderr, "[progress] %s (%s) passed=%t detected=%t\n", res.Name, res.Label, res.Passed, res.Detected)
	}
}

func durationMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
