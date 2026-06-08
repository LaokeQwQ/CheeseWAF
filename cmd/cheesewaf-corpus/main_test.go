package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunAnalyzerModeWritesPassingReport(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	corpus := filepath.Join("..", "..", "internal", "engine", "semantic", "testdata", "curated_external_shapes.jsonl")

	if err := run("analyzer", corpus, "", time.Second, false, "403", output); err != nil {
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

	if err := run("http", corpus, server.URL, time.Second, false, "403", output); err != nil {
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

	if err := run("http", corpus, "", time.Second, false, "403", ""); err == nil {
		t.Fatal("expected missing base URL error")
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
