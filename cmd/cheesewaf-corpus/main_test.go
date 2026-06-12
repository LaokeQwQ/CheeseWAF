package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunAnalyzerModeWritesPassingReport(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	corpus := filepath.Join("..", "..", "internal", "engine", "semantic", "testdata", "curated_external_shapes.jsonl")

	if err := run(options{
		Mode:          "analyzer",
		CorpusPath:    corpus,
		Timeout:       time.Second,
		BlockStatuses: "403",
		OutputPath:    output,
	}); err != nil {
		t.Fatal(err)
	}

	report := readSummary(t, output)
	if report.Mode != "analyzer" {
		t.Fatalf("unexpected mode %q", report.Mode)
	}
	if report.Total == 0 || report.Failures != 0 {
		t.Fatalf("expected passing analyzer corpus, got total=%d failures=%d", report.Total, report.Failures)
	}
	if report.DetectionRate != 1 || report.FalsePositiveRate != 0 {
		t.Fatalf("unexpected rates: detection=%f false_positive=%f", report.DetectionRate, report.FalsePositiveRate)
	}
}

func TestRunHTTPModeUsesConfiguredBlockStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/attack":
			http.Error(w, "blocked", http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	corpus := filepath.Join(t.TempDir(), "corpus.jsonl")
	raw := []byte(`{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/attack"}` + "\n" +
		`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n")
	if err := os.WriteFile(corpus, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "report.json")

	if err := run(options{
		Mode:          "http",
		CorpusPath:    corpus,
		BaseURL:       server.URL,
		Timeout:       time.Second,
		BlockStatuses: "403",
		OutputPath:    output,
	}); err != nil {
		t.Fatal(err)
	}

	report := readSummary(t, output)
	if report.Mode != "http" || report.Failures != 0 {
		t.Fatalf("expected passing HTTP corpus, got mode=%q failures=%d", report.Mode, report.Failures)
	}
	if report.AttackDetected != 1 || report.BenignClean != 1 {
		t.Fatalf("unexpected counters: attack_detected=%d benign_clean=%d", report.AttackDetected, report.BenignClean)
	}
}

func TestRunHTTPModeRequiresBaseURL(t *testing.T) {
	corpus := filepath.Join(t.TempDir(), "corpus.jsonl")
	raw := []byte(`{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/attack"}` + "\n")
	if err := os.WriteFile(corpus, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := run(options{
		Mode:          "http",
		CorpusPath:    corpus,
		Timeout:       time.Second,
		BlockStatuses: "403",
	}); err == nil {
		t.Fatal("expected missing base URL error")
	}
}

func TestRunGateModeAggregatesCorpusAndExternalSuites(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.URL.RawQuery == "":
			w.WriteHeader(http.StatusTeapot)
		case strings.Contains(r.URL.RawQuery, "q="):
			http.Error(w, "blocked", http.StatusForbidden)
		case r.URL.Path == "/attack":
			http.Error(w, "blocked", http.StatusForbidden)
		case r.URL.Path == "/ok":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	corpus := filepath.Join(t.TempDir(), "corpus.jsonl")
	raw := []byte(`{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/attack?q=1%20or%201=1--"}` + "\n" +
		`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n")
	if err := os.WriteFile(corpus, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "gate.json")

	if err := run(options{
		Mode:            "gate",
		CorpusPath:      corpus,
		BaseURL:         server.URL,
		AdminURL:        server.URL,
		Timeout:         time.Second,
		ToolTimeout:     2 * time.Second,
		BlockStatuses:   "403",
		OutputPath:      output,
		NucleiTemplates: filepath.Join("..", "..", "security-validation", "nuclei"),
		SkipExternal:    true,
	}); err != nil {
		t.Fatal(err)
	}

	report := readSummary(t, output)
	if report.Mode != "gate" {
		t.Fatalf("unexpected mode %q", report.Mode)
	}
	if report.Total != 4 {
		t.Fatalf("unexpected total %d", report.Total)
	}
	if len(report.ExternalSuites) == 0 {
		t.Fatal("expected external suite results")
	}
	if report.Warnings == 0 {
		t.Fatal("expected skipped external suites to be counted as warnings")
	}
	if report.Failures != 0 {
		t.Fatalf("expected gate without failures, got warnings=%d failures=%d", report.Warnings, report.Failures)
	}
}

func readSummary(t *testing.T, path string) summary {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report summary
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}
