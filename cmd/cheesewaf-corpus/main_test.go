package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
