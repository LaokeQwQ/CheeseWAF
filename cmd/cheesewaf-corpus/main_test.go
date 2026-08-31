package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/security"
)

func TestRunGovernanceConfigSuccessWritesManifestSummary(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	formal := filepath.Join(dir, "formal.jsonl")
	quarantine := filepath.Join(dir, "quarantine.jsonl")
	manifest := filepath.Join(dir, "manifest.json")
	config := security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
		FormalPath:     formal,
		QuarantinePath: quarantine,
		ManifestPath:   manifest,
	}
	writeGovernanceJSON(t, cfgPath, config)

	var stdout bytes.Buffer
	if err := runGovernance(context.Background(), cfgPath, &stdout); err != nil {
		t.Fatal(err)
	}
	var got security.GovernanceManifest
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("manifest summary is not JSON: %v", err)
	}
	if got.Total != 1 || got.Quarantine != 1 || got.Pipeline == "" {
		t.Fatalf("unexpected governance manifest: %+v", got)
	}
	if _, err := os.Stat(manifest); err != nil {
		t.Fatalf("governance manifest output missing: %v", err)
	}
}

func TestRunGovernanceModeHonorsOutputPath(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	config := security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
		FormalPath:     filepath.Join(dir, "formal.jsonl"),
		QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		ManifestPath:   filepath.Join(dir, "manifest.json"),
	}
	writeGovernanceJSON(t, cfgPath, config)
	summaryPath := filepath.Join(dir, "summary.json")
	if err := runContext(context.Background(), options{Mode: "govern", GovernanceConfigPath: cfgPath, OutputPath: summaryPath}); err != nil {
		t.Fatal(err)
	}
	var got security.GovernanceManifest
	b, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("governance summary is not JSON: %v", err)
	}
	if got.Total != 1 || got.Quarantine != 1 {
		t.Fatalf("unexpected governance summary: %+v", got)
	}
}

func TestRunGovernanceModeRejectsSummaryOverlap(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	original := []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n")
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	config := security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
		FormalPath:     filepath.Join(dir, "formal.jsonl"),
		QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		ManifestPath:   filepath.Join(dir, "manifest.json"),
	}
	writeGovernanceJSON(t, cfgPath, config)

	for name, output := range map[string]string{
		"source":     source,
		"config":     cfgPath,
		"formal":     config.FormalPath,
		"quarantine": config.QuarantinePath,
		"manifest":   config.ManifestPath,
	} {
		t.Run(name, func(t *testing.T) {
			err := runContext(context.Background(), options{Mode: "govern", GovernanceConfigPath: cfgPath, OutputPath: output})
			if err == nil || !strings.Contains(err.Error(), "overlaps protected") {
				t.Fatalf("expected protected-path overlap error, got %v", err)
			}
		})
	}
	got, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("governance summary validation modified the source file")
	}
}

func TestRunGovernanceModeRejectsOutputOverlapWithConfig(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	outputs := []string{
		filepath.Join(dir, "formal.jsonl"),
		filepath.Join(dir, "quarantine.jsonl"),
		filepath.Join(dir, "manifest.json"),
	}
	for _, output := range outputs {
		t.Run(filepath.Base(output), func(t *testing.T) {
			config := security.GovernanceConfig{
				Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
				FormalPath:     outputs[0],
				QuarantinePath: outputs[1],
				ManifestPath:   outputs[2],
			}
			switch output {
			case outputs[0]:
				config.FormalPath = cfgPath
			case outputs[1]:
				config.QuarantinePath = cfgPath
			case outputs[2]:
				config.ManifestPath = cfgPath
			}
			writeGovernanceJSON(t, cfgPath, config)
			before, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			err = runContext(context.Background(), options{Mode: "govern", GovernanceConfigPath: cfgPath})
			if err == nil || !strings.Contains(err.Error(), "overlaps config input") {
				t.Fatalf("expected config overlap error, got %v", err)
			}
			after, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("config file was modified after overlap rejection")
			}
		})
	}
}

func TestRunGovernanceModeRejectsCaseFoldedConfigOverlap(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	writeGovernanceJSON(t, cfgPath, security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
		FormalPath:     strings.ToUpper(cfgPath),
		QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		ManifestPath:   filepath.Join(dir, "manifest.json"),
	})

	err := runContext(context.Background(), options{Mode: "govern", GovernanceConfigPath: cfgPath})
	if err == nil || !strings.Contains(err.Error(), "overlaps config input") {
		t.Fatalf("expected case-folded config overlap error, got %v", err)
	}
}

func TestRunGovernanceModeRejectsReviewPathOverlapWithSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		reviewPath func(t *testing.T) string
	}{
		{name: "exact", reviewPath: func(*testing.T) string { return source }},
		{name: "case-fold", reviewPath: func(*testing.T) string { return strings.ToUpper(source) }},
		{name: "symlink", reviewPath: func(t *testing.T) string {
			alias := filepath.Join(dir, "reviews-alias.jsonl")
			if err := os.Symlink(source, alias); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			return alias
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reviewPath := tc.reviewPath(t)
			cfgPath := filepath.Join(t.TempDir(), "governance.json")
			configDir := filepath.Dir(cfgPath)
			writeGovernanceJSON(t, cfgPath, security.GovernanceConfig{
				Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
				FormalPath:     filepath.Join(configDir, "formal.jsonl"),
				QuarantinePath: filepath.Join(configDir, "quarantine.jsonl"),
				ManifestPath:   filepath.Join(configDir, "manifest.json"),
				ReviewPath:     reviewPath,
			})

			err := runContext(context.Background(), options{Mode: "govern", GovernanceConfigPath: cfgPath})
			if err == nil || !strings.Contains(err.Error(), "governance review path overlaps source input") {
				t.Fatalf("expected review/source overlap error, got %v", err)
			}
		})
	}
}

func TestRunGovernanceModeRejectsCaseFoldedSummaryOverlap(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	writeGovernanceJSON(t, cfgPath, security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
		FormalPath:     filepath.Join(dir, "formal.jsonl"),
		QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		ManifestPath:   filepath.Join(dir, "manifest.json"),
	})

	err := runContext(context.Background(), options{
		Mode:                 "govern",
		GovernanceConfigPath: cfgPath,
		OutputPath:           strings.ToUpper(source),
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps protected") {
		t.Fatalf("expected case-folded summary overlap error, got %v", err)
	}
}

func TestRunGovernanceModeRejectsSummarySymlinkToSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions are platform-specific")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	line := `{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n"
	if err := os.WriteFile(source, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "summary.json")
	if err := os.Symlink(source, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cfgPath := filepath.Join(dir, "governance.json")
	writeGovernanceJSON(t, cfgPath, security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: source, Name: "unit", License: "internal", Access: "local-file"}},
		FormalPath:     filepath.Join(dir, "formal.jsonl"),
		QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		ManifestPath:   filepath.Join(dir, "manifest.json"),
	})
	err := runContext(context.Background(), options{Mode: "govern", GovernanceConfigPath: cfgPath, OutputPath: alias})
	if err == nil || !strings.Contains(err.Error(), "overlaps protected") {
		t.Fatalf("expected symlink overlap error, got %v", err)
	}
}

func TestRunGovernanceInputErrors(t *testing.T) {
	dir := t.TempDir()
	invalidJSON := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts options
		want string
	}{
		{name: "unknown mode", opts: options{Mode: "unknown"}, want: `unsupported mode "unknown"`},
		{name: "missing config", opts: options{Mode: "govern"}, want: "--governance-config is required"},
		{name: "invalid JSON", opts: options{Mode: "govern", GovernanceConfigPath: invalidJSON}, want: "parse governance config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runContext(context.Background(), tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunGovernancePropagatesCoreErrors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "governance.json")
	config := security.GovernanceConfig{
		Sources:        []security.SourceSpec{{Path: filepath.Join(dir, "missing.jsonl"), License: "internal", Access: "local-file"}},
		FormalPath:     filepath.Join(dir, "formal.jsonl"),
		QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		ManifestPath:   filepath.Join(dir, "manifest.json"),
	}
	writeGovernanceJSON(t, cfgPath, config)
	err := runGovernance(context.Background(), cfgPath, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "open "+config.Sources[0].Path) {
		t.Fatalf("expected governance core source error, got %v", err)
	}
}

func TestRunGovernanceHonorsCanceledContext(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "governance.json")
	writeGovernanceJSON(t, cfgPath, security.GovernanceConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runWithContext(ctx, options{Mode: "govern", GovernanceConfigPath: cfgPath})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func writeGovernanceJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

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

func TestExternalSuitesUseDockerFallbackWhenToolsAreMissing(t *testing.T) {
	templateRoot := t.TempDir()
	for _, dir := range []string{"data", "admin"} {
		path := filepath.Join(templateRoot, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "negative.yaml"), []byte("id: unit\ninfo:\n  name: unit\n  severity: info\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var commands []suiteCommand
	restore := stubExternalExecution(t,
		func(name string) (string, error) {
			if name == "docker" {
				return "docker", nil
			}
			return "", exec.ErrNotFound
		},
		func(ctx context.Context, spec suiteCommand, classify func(string, int, error) suiteResult) suiteResult {
			commands = append(commands, spec)
			return classify("", 0, nil)
		},
	)
	defer restore()

	opts := options{ToolTimeout: time.Second, NucleiTemplates: templateRoot, Insecure: true}
	results := []suiteResult{
		runSqlmapSuite(context.Background(), opts, "http://127.0.0.1:8080/?q=1"),
		runXSStrikeSuite(context.Background(), opts, "http://localhost:8080/?q=test"),
		runNucleiDataSuite(context.Background(), opts, "https://127.0.0.1:9443/"),
		runNucleiAdminSuite(context.Background(), opts, "https://127.0.0.1:9443/__bad-entry"),
	}
	for _, result := range results {
		if result.Artifact == "" {
			continue
		}
		artifact := result.Artifact
		t.Cleanup(func() {
			_ = os.RemoveAll(artifact)
		})
	}

	if len(commands) != 4 {
		t.Fatalf("expected four docker-backed scanner commands, got %d", len(commands))
	}
	for i, command := range commands {
		if command.Tool != "docker" {
			t.Fatalf("command %d should use docker fallback, got %q", i, command.Tool)
		}
		if !containsArg(command.Args, "host.docker.internal") {
			t.Fatalf("command %d should rewrite localhost target for docker, args=%v", i, command.Args)
		}
		if strings.HasPrefix(command.Name, "nuclei-") && hasExactArg(command.Args, "-insecure") {
			t.Fatalf("nuclei command %d should not pass removed -insecure flag, args=%v", i, command.Args)
		}
	}
	for _, wantImage := range []string{defaultSQLMapDockerImage, defaultXSStrikeDockerImage, defaultNucleiDockerImage} {
		if !anyCommandContains(commands, wantImage) {
			t.Fatalf("expected docker command to include image %q, commands=%v", wantImage, commands)
		}
	}
	for _, result := range results {
		if result.Status != "passed" {
			t.Fatalf("expected fallback result to pass under empty scanner output, got %+v", result)
		}
		if len(result.Command) == 0 || result.Command[0] != "docker" {
			t.Fatalf("expected recorded docker command, got %+v", result.Command)
		}
	}
	if results[0].Artifact == "" {
		t.Fatalf("expected sqlmap fallback to record its output artifact directory")
	}
}

func TestZAPSuiteUsesDockerFallbackAndImageOverride(t *testing.T) {
	t.Setenv("CHEESEWAF_ZAP_DOCKER_IMAGE", "registry.local/zap:stable")
	var commands []suiteCommand
	restore := stubExternalExecution(t,
		func(name string) (string, error) {
			if name == "docker" {
				return "docker", nil
			}
			return "", exec.ErrNotFound
		},
		func(ctx context.Context, spec suiteCommand, classify func(string, int, error) suiteResult) suiteResult {
			commands = append(commands, spec)
			return classify("", 0, nil)
		},
	)
	defer restore()

	res := runZAPSuite(context.Background(), options{ToolTimeout: time.Second, Insecure: true}, "https://127.0.0.1:9443")
	if res.Artifact != "" {
		t.Cleanup(func() {
			_ = os.RemoveAll(filepath.Dir(res.Artifact))
		})
	}
	if res.Status != "passed" {
		t.Fatalf("expected ZAP fallback to pass under empty scanner output, got %+v", res)
	}
	if len(commands) != 1 || commands[0].Tool != "docker" {
		t.Fatalf("expected one docker-backed ZAP command, got %+v", commands)
	}
	if !containsArg(commands[0].Args, "registry.local/zap:stable") {
		t.Fatalf("expected ZAP image override, args=%v", commands[0].Args)
	}
	if !containsArg(commands[0].Args, "host.docker.internal") {
		t.Fatalf("expected localhost rewrite for ZAP container, args=%v", commands[0].Args)
	}
}

func TestSQLMapClassifierTreatsProtectedNotInjectableOutputAsPassed(t *testing.T) {
	output := `[INFO] checking if the target is protected by some kind of WAF/IPS
[CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS
[INFO] testing for SQL injection on GET parameter 'q'
[WARNING] GET parameter 'q' does not seem to be injectable
[ERROR] all tested parameters do not appear to be injectable.
[WARNING] HTTP error codes detected during run:
403 (Forbidden) - 60 times`

	status, findings := classifySQLMapStatus(output, 1)
	if status != "passed" || findings != 0 {
		t.Fatalf("expected protected non-injectable output to pass, got status=%q findings=%d", status, findings)
	}
}

func TestSQLMapClassifierFailsOnInjectionEvidence(t *testing.T) {
	output := `sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 1=1
---`

	status, findings := classifySQLMapStatus(output, 0)
	if status != "failed" || findings != 1 {
		t.Fatalf("expected injection evidence to fail, got status=%q findings=%d", status, findings)
	}
}

func TestZAPClassifierTreatsWarnOnlyBaselineAsPassed(t *testing.T) {
	output := `WARN-NEW: Non-Storable Content [10049] x 3
WARN-NEW: CSP: Wildcard Directive [10055] x 4
FAIL-NEW: 0	FAIL-INPROG: 0	WARN-NEW: 2	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 65`

	status, findings := classifyZAPStatus(output, 2)
	if status != "passed" || findings != 0 {
		t.Fatalf("expected WARN-only ZAP baseline to pass, got status=%q findings=%d", status, findings)
	}
}

func TestZAPClassifierFailsOnFailCounts(t *testing.T) {
	output := `FAIL-NEW: 1	FAIL-INPROG: 2	WARN-NEW: 0	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 65`

	status, findings := classifyZAPStatus(output, 1)
	if status != "failed" || findings != 3 {
		t.Fatalf("expected ZAP fail counts to fail, got status=%q findings=%d", status, findings)
	}
}

func TestExternalSuitesSkipWhenToolAndDockerAreMissing(t *testing.T) {
	restore := stubExternalExecution(t,
		func(name string) (string, error) {
			return "", exec.ErrNotFound
		},
		func(ctx context.Context, spec suiteCommand, classify func(string, int, error) suiteResult) suiteResult {
			t.Fatalf("scanner command should not run when %s and docker are missing", spec.Name)
			return suiteResult{}
		},
	)
	defer restore()

	res := runXSStrikeSuite(context.Background(), options{ToolTimeout: time.Second}, "http://example.test/?q=test")
	if res.Status != "skipped" {
		t.Fatalf("expected skipped result, got %+v", res)
	}
	if !strings.Contains(res.Error, "docker is not available") {
		t.Fatalf("expected docker availability error, got %q", res.Error)
	}
}

func TestDockerReachableTargetRewritesLocalhostWithoutPort(t *testing.T) {
	target, args, err := dockerReachableTarget("http://127.0.0.1/path")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target, "http://host.docker.internal/path") {
		t.Fatalf("unexpected rewritten target %q", target)
	}
	if strings.Contains(target, "host.docker.internal:") {
		t.Fatalf("rewritten target should not include an empty port: %q", target)
	}
	if runtime.GOOS == "linux" && !containsArg(args, "host.docker.internal:host-gateway") {
		t.Fatalf("expected linux docker host-gateway arg, got %v", args)
	}
}

func TestDockerImageUsesEnvOverride(t *testing.T) {
	t.Setenv("CHEESEWAF_TEST_SCANNER_IMAGE", "registry.local/scanner@sha256:abc")
	got := dockerImage("CHEESEWAF_TEST_SCANNER_IMAGE", "default:latest")
	if got != "registry.local/scanner@sha256:abc" {
		t.Fatalf("expected docker image env override, got %q", got)
	}
}

func TestRunStreamModeWritesNDJSONAndSummary(t *testing.T) {
	corpus := filepath.Join(t.TempDir(), "corpus.jsonl")
	raw := []byte(`{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/?q=1%20or%201=1--"}` + "\n" +
		`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n")
	if err := os.WriteFile(corpus, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	ndjson := filepath.Join(outDir, "results.jsonl")

	if err := run(options{
		Mode:       "analyzer",
		CorpusPath: corpus,
		Timeout:    time.Second,
		OutputPath: ndjson,
		Shards:     1,
		Stream:     true,
	}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(ndjson)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON result lines, got %d", len(lines))
	}
	for i, line := range lines {
		var res result
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if res.Name == "" || res.Label == "" {
			t.Fatalf("line %d missing result fields: %s", i, line)
		}
	}

	rep := readSummary(t, ndjson+".summary.json")
	if rep.Mode != "analyzer" {
		t.Fatalf("unexpected mode %q", rep.Mode)
	}
	if rep.Total != 2 || rep.Failures != 0 {
		t.Fatalf("expected passing streamed corpus, got total=%d failures=%d", rep.Total, rep.Failures)
	}
	if rep.AttackDetected != 1 || rep.BenignClean != 1 {
		t.Fatalf("unexpected counters: attack_detected=%d benign_clean=%d", rep.AttackDetected, rep.BenignClean)
	}
}

func TestRunStreamModeWritesFailureArtifactsBeforeReturningError(t *testing.T) {
	corpus := writeCorpus(t, `{"name":"missed-attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/ok"}`+"\n")
	output := filepath.Join(t.TempDir(), "results.jsonl")

	err := run(options{
		Mode:       "analyzer",
		CorpusPath: corpus,
		OutputPath: output,
		Shards:     1,
		Stream:     true,
	})
	if err == nil || !strings.Contains(err.Error(), "security corpus validation failed: 1/1 cases failed") {
		t.Fatalf("expected streamed validation failure, got %v", err)
	}

	data, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var res result
	if err := json.Unmarshal(bytes.TrimSpace(data), &res); err != nil {
		t.Fatalf("stream output is not valid NDJSON: %v", err)
	}
	if res.Name != "missed-attack" || res.Passed {
		t.Fatalf("unexpected streamed result: %+v", res)
	}

	report := readSummary(t, output+".summary.json")
	if report.Total != 1 || report.Failures != 1 || report.AttackMissed != 1 {
		t.Fatalf("unexpected failure summary: %+v", report)
	}
}

func TestCorpusCLIStreamFailureExitsNonzeroAfterWritingArtifacts(t *testing.T) {
	corpus := writeCorpus(t, `{"name":"missed-attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/ok"}`+"\n")
	output := filepath.Join(t.TempDir(), "results.jsonl")
	binary := filepath.Join(t.TempDir(), "cheesewaf-corpus")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}

	build := exec.Command("go", "build", "-o", binary, ".")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build corpus CLI: %v\n%s", err, data)
	}
	cmd := exec.Command(binary,
		"-mode", "analyzer",
		"-corpus", corpus,
		"-output", output,
		"-stream",
	)
	data, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("expected nonzero corpus CLI exit, got err=%v output=%s", err, data)
	}
	if !strings.Contains(string(data), "security corpus validation failed: 1/1 cases failed") {
		t.Fatalf("expected validation error on stderr, got %s", data)
	}

	report := readSummary(t, output+".summary.json")
	if report.Total != 1 || report.Failures != 1 {
		t.Fatalf("unexpected subprocess summary: %+v", report)
	}
}

func TestRunStreamModeRejectsEmptyCorpus(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "blank-only", raw: " \n\t\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corpus := writeCorpus(t, tc.raw)
			err := run(options{Mode: "analyzer", CorpusPath: corpus, Shards: 1, Stream: true})
			if err == nil || err.Error() != "corpus is empty" {
				t.Fatalf("expected corpus is empty error, got %v", err)
			}
		})
	}
}

func TestRunStreamModeDistinguishesEmptyCorpusFromEmptyShard(t *testing.T) {
	corpus := writeCorpus(t, "\n\t\n")
	err := run(options{Mode: "analyzer", CorpusPath: corpus, Shards: 2, Shard: 1, Stream: true})
	if err == nil || err.Error() != "corpus is empty" {
		t.Fatalf("expected corpus is empty error, got %v", err)
	}
}

func TestRunNonStreamUsesRawLineShardMembership(t *testing.T) {
	const shards = 2
	var raw []byte
	var selectedShard int
	for i := 0; i < 100; i++ {
		candidate := []byte(fmt.Sprintf(`{"name":"raw-shard-%d","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`, i))
		byRaw := security.ShardIndexForRaw(candidate, shards)
		byName := security.ShardIndexFor(fmt.Sprintf("raw-shard-%d", i), shards)
		if byRaw != byName {
			raw = candidate
			selectedShard = byRaw
			break
		}
	}
	if len(raw) == 0 {
		t.Fatal("failed to construct raw/name shard mismatch")
	}
	corpus := writeCorpus(t, string(raw)+"\n")
	output := filepath.Join(t.TempDir(), "report.json")
	if err := run(options{
		Mode:       "analyzer",
		CorpusPath: corpus,
		OutputPath: output,
		Shards:     shards,
		Shard:      selectedShard,
	}); err != nil {
		t.Fatalf("raw-line selected shard must run in non-stream mode: %v", err)
	}
	if report := readSummary(t, output); report.Total != 1 {
		t.Fatalf("non-stream raw shard report = %+v, want one selected case", report)
	}
}

func TestRunStreamModeRejectsInvalidShardParameters(t *testing.T) {
	corpus := writeCorpus(t, `{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n")
	for _, tc := range []struct {
		name   string
		shards int
		shard  int
		want   string
	}{
		{name: "zero shards", shards: 0, shard: 0, want: "--shards must be at least 1"},
		{name: "negative shard", shards: 2, shard: -1, want: "--shard must be between 0 and 1 for --shards=2"},
		{name: "shard equals count", shards: 2, shard: 2, want: "--shard must be between 0 and 1 for --shards=2"},
		{name: "nonzero unsharded index", shards: 1, shard: 1, want: "--shard must be between 0 and 0 for --shards=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(options{
				Mode:       "analyzer",
				CorpusPath: corpus,
				Shards:     tc.shards,
				Shard:      tc.shard,
				Stream:     true,
			})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunStreamModeRejectsEmptySelectedShard(t *testing.T) {
	raw := []byte(`{"name":"only-case","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`)
	selectedShard := 1 - security.ShardIndexForRaw(raw, 2)
	corpus := writeCorpus(t, string(raw)+"\n")

	err := run(options{
		Mode:       "analyzer",
		CorpusPath: corpus,
		Shards:     2,
		Shard:      selectedShard,
		Stream:     true,
	})
	if err == nil || err.Error() != "corpus shard is empty" {
		t.Fatalf("expected corpus shard is empty error, got %v", err)
	}
}

func TestRunStreamGateFailureWritesSummaryBeforeReturningError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	corpus := writeCorpus(t, `{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n")
	output := filepath.Join(t.TempDir(), "results.jsonl")
	err := run(options{
		Mode:            "gate",
		CorpusPath:      corpus,
		BaseURL:         server.URL,
		AdminURL:        server.URL,
		BlockStatuses:   "403",
		OutputPath:      output,
		RequireExternal: true,
		SkipExternal:    true,
		Shards:          1,
		Stream:          true,
	})
	if err == nil || !strings.Contains(err.Error(), "security corpus validation failed") {
		t.Fatalf("expected gate validation failure, got %v", err)
	}

	report := readSummary(t, output+".summary.json")
	if report.Total != 2 || report.Failures != 5 || len(report.ExternalSuites) != 5 {
		t.Fatalf("unexpected gate failure summary: %+v", report)
	}
}

func TestLocalCorpusRequestConstructionErrorsAreWarnings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	corpus := writeCorpus(t,
		`{"name":"bad-method","source_family":"unit","label":"benign","method":"GET\\nBAD","target":"/ok"}`+"\n"+
			`{"name":"bad-target","source_family":"unit","label":"benign","method":"GET","target":"%gh"}`+"\n",
	)
	for _, mode := range []string{"analyzer", "http"} {
		t.Run(mode, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report.json")
			err := run(options{
				Mode:          mode,
				CorpusPath:    corpus,
				BaseURL:       server.URL,
				BlockStatuses: "403",
				OutputPath:    output,
			})
			if err != nil {
				t.Fatalf("local construction error should be a warning: %v", err)
			}

			report := readSummary(t, output)
			if report.Total != 2 || report.Warnings != 2 || report.Failures != 0 {
				t.Fatalf("unexpected local construction summary: %+v", report)
			}
			for _, res := range report.Results {
				if !res.Warning || !res.Passed || res.Error == "" {
					t.Fatalf("unexpected local construction result: %+v", res)
				}
			}
		})
	}
}

func TestHTTPTransportErrorsRemainFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	baseURL := server.URL
	server.Close()

	corpus := writeCorpus(t, `{"name":"transport-error","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n")
	output := filepath.Join(t.TempDir(), "report.json")
	err := run(options{
		Mode:          "http",
		CorpusPath:    corpus,
		BaseURL:       baseURL,
		Timeout:       time.Second,
		BlockStatuses: "403",
		OutputPath:    output,
	})
	if err == nil || !strings.Contains(err.Error(), "security corpus validation failed") {
		t.Fatalf("expected HTTP transport failure, got %v", err)
	}

	report := readSummary(t, output)
	if report.Total != 1 || report.Failures != 1 || report.Warnings != 0 {
		t.Fatalf("unexpected transport failure summary: %+v", report)
	}
	if len(report.Results) != 1 || report.Results[0].Warning || report.Results[0].Error == "" {
		t.Fatalf("unexpected transport failure result: %+v", report.Results)
	}
}

func TestRunAnalyzerModeReadsGzipCorpus(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus.jsonl.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := fmt.Fprint(gz, `{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/?q=1%20or%201=1--"}`+"\n"+`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpus, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "report.json")
	if err := run(options{
		Mode:       "analyzer",
		CorpusPath: corpus,
		Timeout:    time.Second,
		OutputPath: output,
	}); err != nil {
		t.Fatal(err)
	}
	rep := readSummary(t, output)
	if rep.Total != 2 || rep.Failures != 0 {
		t.Fatalf("expected passing gzip corpus, got total=%d failures=%d", rep.Total, rep.Failures)
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

func writeCorpus(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func stubExternalExecution(t *testing.T, lookPath func(string) (string, error), run func(context.Context, suiteCommand, func(string, int, error) suiteResult) suiteResult) func() {
	t.Helper()
	oldLookPath := lookupExecutable
	oldRun := executeSuiteCommand
	lookupExecutable = lookPath
	executeSuiteCommand = run
	return func() {
		lookupExecutable = oldLookPath
		executeSuiteCommand = oldRun
	}
}

func containsArg(args []string, needle string) bool {
	for _, arg := range args {
		if strings.Contains(arg, needle) {
			return true
		}
	}
	return false
}

func hasExactArg(args []string, needle string) bool {
	for _, arg := range args {
		if arg == needle {
			return true
		}
	}
	return false
}

func anyCommandContains(commands []suiteCommand, needle string) bool {
	for _, command := range commands {
		if containsArg(command.Args, needle) {
			return true
		}
	}
	return false
}
