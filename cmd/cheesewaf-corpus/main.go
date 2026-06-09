package main

import (
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
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
	Error            string  `json:"error,omitempty"`
}

type summary struct {
	Mode              string    `json:"mode"`
	Corpus            string    `json:"corpus"`
	BaseURL           string    `json:"base_url,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	DurationMS        float64   `json:"duration_ms"`
	Total             int       `json:"total"`
	AttackTotal       int       `json:"attack_total"`
	AttackDetected    int       `json:"attack_detected"`
	AttackMissed      int       `json:"attack_missed"`
	BenignTotal       int       `json:"benign_total"`
	BenignClean       int       `json:"benign_clean"`
	FalsePositive     int       `json:"false_positive"`
	Failures          int       `json:"failures"`
	DetectionRate     float64   `json:"detection_rate"`
	FalsePositiveRate float64   `json:"false_positive_rate"`
	Results           []result  `json:"results"`
}

func main() {
	var (
		mode          = flag.String("mode", "analyzer", "validation mode: analyzer or http")
		corpusPath    = flag.String("corpus", "internal/engine/semantic/testdata/curated_external_shapes.jsonl", "JSONL corpus path")
		baseURL       = flag.String("base-url", "", "base URL for http mode, for example http://127.0.0.1:8080")
		timeout       = flag.Duration("timeout", 10*time.Second, "per-request timeout in http mode")
		insecure      = flag.Bool("insecure", false, "skip TLS certificate verification in http mode")
		blockStatuses = flag.String("block-statuses", "403,406,429,451,503", "comma-separated statuses treated as WAF block/challenge")
		outputPath    = flag.String("output", "", "write JSON report to file instead of stdout")
	)
	flag.Parse()

	if err := run(*mode, *corpusPath, *baseURL, *timeout, *insecure, *blockStatuses, *outputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(mode, corpusPath, baseURL string, timeout time.Duration, insecure bool, rawBlockStatuses, outputPath string) error {
	file, err := os.Open(corpusPath)
	if err != nil {
		return err
	}
	defer file.Close()

	cases, err := securitytest.LoadJSONL(file)
	if err != nil {
		return err
	}
	if len(cases) == 0 {
		return errors.New("corpus is empty")
	}

	started := time.Now().UTC()
	report := summary{
		Mode:      mode,
		Corpus:    corpusPath,
		BaseURL:   baseURL,
		StartedAt: started,
		Total:     len(cases),
		Results:   make([]result, 0, len(cases)),
	}

	switch mode {
	case "analyzer":
		for _, tc := range cases {
			report.add(validateAnalyzer(tc))
		}
	case "http":
		if strings.TrimSpace(baseURL) == "" {
			return errors.New("--base-url is required in http mode")
		}
		statuses, err := parseBlockStatuses(rawBlockStatuses)
		if err != nil {
			return err
		}
		client := httpClient(timeout, insecure)
		for _, tc := range cases {
			report.add(validateHTTP(client, baseURL, statuses, tc))
		}
	default:
		return fmt.Errorf("unsupported mode %q", mode)
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

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if outputPath == "" {
		_, err = os.Stdout.Write(encoded)
	} else {
		err = os.WriteFile(outputPath, encoded, 0o644)
	}
	if err != nil {
		return err
	}
	if report.Failures > 0 {
		return fmt.Errorf("security corpus validation failed: %d/%d cases failed", report.Failures, report.Total)
	}
	return nil
}

func validateAnalyzer(tc securitytest.Case) result {
	res := baseResult("analyzer", tc)
	start := time.Now()

	req, err := newCorpusRequest(tc)
	if err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	reqCtx, err := engine.NewRequestContext(req, "corpus")
	if err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	detection, err := semantic.NewAnalyzer("block").Detect(context.Background(), reqCtx)
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
		res.Passed = res.Detected && res.DetectorCategory == tc.Category
	case "benign":
		res.Passed = !res.Detected
	}
	res.LatencyMS = durationMS(time.Since(start))
	return res
}

func validateHTTP(client *http.Client, baseURL string, blockStatuses map[int]struct{}, tc securitytest.Case) result {
	res := baseResult("http", tc)
	start := time.Now()

	target, err := resolveTarget(baseURL, tc.Target)
	if err != nil {
		res.Error = err.Error()
		res.LatencyMS = durationMS(time.Since(start))
		return res
	}
	req, err := http.NewRequest(tc.Method, target, strings.NewReader(tc.Body))
	if err != nil {
		res.Error = err.Error()
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
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
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
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("base URL %q must include scheme and host", baseURL)
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

func (s *summary) add(res result) {
	s.Results = append(s.Results, res)
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

func durationMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
