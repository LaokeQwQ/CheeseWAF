package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/securitytest"
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

type options struct {
	Mode            string
	CorpusPath      string
	BaseURL         string
	AdminURL        string
	Timeout         time.Duration
	ToolTimeout     time.Duration
	Insecure        bool
	BlockStatuses   string
	OutputPath      string
	NucleiTemplates string
	RequireExternal bool
	SkipExternal    bool
	Workers         int
	Shards          int
	Shard           int
	Stream          bool
	Progress        bool
}

func main() {
	var (
		mode            = flag.String("mode", "analyzer", "validation mode: analyzer, http, or gate")
		corpusPath      = flag.String("corpus", "internal/engine/semantic/testdata/curated_external_shapes.jsonl", "JSONL corpus path")
		baseURL         = flag.String("base-url", "", "base URL for http/gate mode, for example http://127.0.0.1:8080")
		adminURL        = flag.String("admin-url", "", "admin-plane base URL for gate mode; defaults to base URL when empty")
		timeout         = flag.Duration("timeout", 10*time.Second, "per-request timeout in http mode")
		toolTimeout     = flag.Duration("tool-timeout", 10*time.Minute, "per-tool timeout in gate mode")
		insecure        = flag.Bool("insecure", false, "skip TLS certificate verification in http mode and supported gate scanners")
		blockStatuses   = flag.String("block-statuses", "403,406,429,451,503", "comma-separated statuses treated as WAF block/challenge")
		outputPath      = flag.String("output", "", "write JSON report to file instead of stdout")
		nucleiTemplates = flag.String("nuclei-templates", "security-validation/nuclei", "nuclei template directory for gate mode")
		requireExternal = flag.Bool("require-external", false, "fail gate mode when an external scanner is missing instead of skipping")
		skipExternal    = flag.Bool("skip-external", false, "skip external scanner wrappers in gate mode and run only analyzer/http replay")
		workers         = flag.Int("workers", 0, "concurrent workers for analyzer/http replay (0 = GOMAXPROCS)")
		shards          = flag.Int("shards", 1, "number of corpus shards (1 = no sharding)")
		shard           = flag.Int("shard", 0, "shard index to process (0-based; requires -shards > 1)")
		stream          = flag.Bool("stream", false, "stream per-case results as JSON lines instead of collecting the full report")
		progress        = flag.Bool("progress", false, "print per-case progress lines to stderr")
	)
	flag.Parse()

	if err := run(options{
		Mode:            *mode,
		CorpusPath:      *corpusPath,
		BaseURL:         *baseURL,
		AdminURL:        *adminURL,
		Timeout:         *timeout,
		ToolTimeout:     *toolTimeout,
		Insecure:        *insecure,
		BlockStatuses:   *blockStatuses,
		OutputPath:      *outputPath,
		NucleiTemplates: *nucleiTemplates,
		RequireExternal: *requireExternal,
		SkipExternal:    *skipExternal,
		Workers:         *workers,
		Shards:          *shards,
		Shard:           *shard,
		Stream:          *stream,
		Progress:        *progress,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	file, err := os.Open(opts.CorpusPath)
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

	cases, err := securitytest.LoadJSONL(reader)
	if err != nil {
		return err
	}
	if len(cases) == 0 {
		return errors.New("corpus is empty")
	}
	if opts.Shards > 1 {
		cases = securitytest.FilterShard(cases, opts.Shards, opts.Shard)
		if len(cases) == 0 {
			return errors.New("corpus shard is empty")
		}
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
		for _, res := range runConcurrent(cases, opts.Workers, func(tc securitytest.Case) result {
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
		for _, res := range runConcurrent(cases, opts.Workers, func(tc securitytest.Case) result {
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
		for _, res := range runConcurrent(cases, opts.Workers, func(tc securitytest.Case) result {
			return validateAnalyzer(analyzer, tc)
		}) {
			report.addReport(res, opts.Progress)
		}
		for _, res := range runConcurrent(cases, opts.Workers, func(tc securitytest.Case) result {
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

	process := func(tc securitytest.Case) []result {
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

	cases := make(chan securitytest.Case, workers*2)
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

	loadErr := make(chan error, 1)
	producerDone := make(chan struct{})
	selectedCases := 0
	go func() {
		defer close(producerDone)
		defer close(cases)
		if err := securitytest.ForEachJSONL(reader, opts.Shards, opts.Shard, func(tc securitytest.Case) error {
			selectedCases++
			cases <- tc
			return nil
		}); err != nil {
			loadErr <- err
		}
	}()

	writerDone := make(chan error, 1)
	go func() {
		writerDone <- writeStreamResults(opts, out, results, &report)
	}()

	<-producerDone
	workersWG.Wait()
	close(results)
	if err := <-writerDone; err != nil {
		return err
	}
	select {
	case err := <-loadErr:
		if err != nil {
			return err
		}
	default:
	}
	if selectedCases == 0 {
		if opts.Shards > 1 {
			return errors.New("corpus shard is empty")
		}
		return errors.New("corpus is empty")
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
	if shards < 1 {
		return errors.New("--shards must be at least 1")
	}
	if shard < 0 || shard >= shards {
		return fmt.Errorf("--shard must be between 0 and %d for --shards=%d", shards-1, shards)
	}
	return nil
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

func runConcurrent(cases []securitytest.Case, workers int, fn func(securitytest.Case) result) []result {
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

func validateAnalyzer(analyzer *semantic.Analyzer, tc securitytest.Case) result {
	res := baseResult("analyzer", tc)
	start := time.Now()

	req, err := newCorpusRequest(tc)
	if err != nil {
		res.Error = err.Error()
		res.Passed = true
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	reqCtx, err := engine.NewRequestContext(req, "corpus")
	if err != nil {
		res.Error = err.Error()
		res.Passed = true
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	detection, err := analyzer.Detect(context.Background(), reqCtx)
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
		if securitytest.StrictCategory(tc.SourceFamily) {
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

func validateHTTP(client *http.Client, baseURL string, blockStatuses map[int]struct{}, tc securitytest.Case) result {
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
		res.Passed = true
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	req, err := http.NewRequest(tc.Method, target, strings.NewReader(tc.Body))
	if err != nil {
		res.Error = err.Error()
		res.Passed = true
		res.Warning = true
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	req.Header.Set("User-Agent", "CheeseWAF-Corpus-Runner/0.1")
	for key, value := range tc.Header {
		req.Header.Set(key, value)
	}
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

func baseResult(mode string, tc securitytest.Case) result {
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

func newCorpusRequest(tc securitytest.Case) (*http.Request, error) {
	req, err := http.NewRequest(tc.Method, tc.Target, strings.NewReader(tc.Body))
	if err != nil {
		return nil, err
	}
	if tc.ContentType != "" {
		req.Header.Set("Content-Type", tc.ContentType)
	}
	for key, value := range tc.Header {
		req.Header.Set(key, value)
	}
	return req, nil
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
