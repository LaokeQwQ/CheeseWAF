package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSQLMapDockerImage   = "parrotsec/sqlmap:latest"
	defaultXSStrikeDockerImage = "femtopixel/xsstrike:latest"
	defaultNucleiDockerImage   = "projectdiscovery/nuclei:latest"
	defaultZAPDockerImage      = "ghcr.io/zaproxy/zaproxy:stable"
)

var (
	lookupExecutable    = exec.LookPath
	executeSuiteCommand = runExternalCommand
)

type suiteResult struct {
	Name       string   `json:"name"`
	Tool       string   `json:"tool"`
	Target     string   `json:"target"`
	Command    []string `json:"command,omitempty"`
	Status     string   `json:"status"`
	ExitCode   int      `json:"exit_code,omitempty"`
	Findings   int      `json:"findings,omitempty"`
	DurationMS float64  `json:"duration_ms"`
	Output     string   `json:"output,omitempty"`
	Error      string   `json:"error,omitempty"`
	Artifact   string   `json:"artifact,omitempty"`
}

func runGateSuites(report *summary, opts options) error {
	if report == nil {
		return errors.New("report is required")
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		return errors.New("--base-url is required in gate mode")
	}

	dataTarget, err := resolveTarget(opts.BaseURL, "/")
	if err != nil {
		return err
	}
	sqlTarget, err := resolveTarget(opts.BaseURL, "/?q=1")
	if err != nil {
		return err
	}
	xssTarget, err := resolveTarget(opts.BaseURL, "/?q=test")
	if err != nil {
		return err
	}

	if opts.SkipExternal {
		report.ExternalSuites = append(report.ExternalSuites, skippedExternalSuites(opts)...)
		for _, suite := range report.ExternalSuites {
			report.addSuite(suite, opts.RequireExternal)
		}
		return nil
	}

	ctx := context.Background()
	report.ExternalSuites = append(report.ExternalSuites, runSqlmapSuite(ctx, opts, sqlTarget))
	report.ExternalSuites = append(report.ExternalSuites, runXSStrikeSuite(ctx, opts, xssTarget))
	report.ExternalSuites = append(report.ExternalSuites, runNucleiDataSuite(ctx, opts, dataTarget))
	if strings.TrimSpace(opts.AdminURL) != "" {
		adminTarget := opts.AdminURL
		report.ExternalSuites = append(report.ExternalSuites, runNucleiAdminSuite(ctx, opts, adminTarget))
		report.ExternalSuites = append(report.ExternalSuites, runZAPSuite(ctx, opts, adminTarget))
	} else {
		report.ExternalSuites = append(report.ExternalSuites, suiteResult{
			Name:   "nuclei-admin",
			Tool:   "nuclei",
			Target: "",
			Status: "skipped",
			Error:  "admin-url not provided",
		})
		report.ExternalSuites = append(report.ExternalSuites, suiteResult{
			Name:   "zap-baseline",
			Tool:   "zap-baseline.py",
			Target: "",
			Status: "skipped",
			Error:  "admin-url not provided",
		})
	}

	for _, suite := range report.ExternalSuites {
		report.addSuite(suite, opts.RequireExternal)
	}
	return nil
}

func skippedExternalSuites(opts options) []suiteResult {
	adminTarget := strings.TrimSpace(opts.AdminURL)
	return []suiteResult{
		{Name: "sqlmap", Tool: "sqlmap", Target: "", Status: "skipped", Error: "external scanner execution disabled"},
		{Name: "xsstrike", Tool: "xsstrike", Target: "", Status: "skipped", Error: "external scanner execution disabled"},
		{Name: "nuclei-data", Tool: "nuclei", Target: strings.TrimSpace(opts.BaseURL), Status: "skipped", Error: "external scanner execution disabled"},
		{Name: "nuclei-admin", Tool: "nuclei", Target: adminTarget, Status: "skipped", Error: "external scanner execution disabled"},
		{Name: "zap-baseline", Tool: "zap-baseline.py", Target: adminTarget, Status: "skipped", Error: "external scanner execution disabled"},
	}
}

func (s *summary) addSuite(res suiteResult, strict bool) {
	switch res.Status {
	case "passed":
		return
	case "warning", "skipped":
		s.Warnings++
		if strict {
			s.Failures++
		}
	default:
		s.Failures++
	}
}

func runSqlmapSuite(ctx context.Context, opts options, target string) suiteResult {
	if _, err := lookupExecutable("sqlmap"); err == nil {
		outputDir, err := os.MkdirTemp("", "cheesewaf-sqlmap-*")
		if err != nil {
			return suiteResult{Name: "sqlmap", Tool: "sqlmap", Target: target, Status: "failed", Error: err.Error()}
		}
		args := sqlmapArgs(target, outputDir)
		return executeSuiteCommand(ctx, suiteCommand{
			Name:    "sqlmap",
			Tool:    "sqlmap",
			Target:  target,
			Args:    args,
			Timeout: opts.ToolTimeout,
		}, classifySQLMapResult(opts, target, append([]string{"sqlmap"}, args...), outputDir))
	}

	if _, err := lookupExecutable("docker"); err != nil {
		return suiteResult{
			Name:   "sqlmap",
			Tool:   "sqlmap",
			Target: target,
			Status: "skipped",
			Error:  "sqlmap not found in PATH and docker is not available",
		}
	}

	rewrittenTarget, dockerHostArgs, err := dockerReachableTarget(target)
	if err != nil {
		return suiteResult{Name: "sqlmap", Tool: "sqlmap", Target: target, Status: "failed", Error: err.Error()}
	}
	outputDir, err := os.MkdirTemp("", "cheesewaf-sqlmap-*")
	if err != nil {
		return suiteResult{Name: "sqlmap", Tool: "sqlmap", Target: target, Status: "failed", Error: err.Error()}
	}
	if err := os.Chmod(outputDir, 0o777); err != nil {
		return suiteResult{Name: "sqlmap", Tool: "sqlmap", Target: target, Status: "failed", Error: err.Error()}
	}
	args := sqlmapArgs(rewrittenTarget, "/output")
	runArgs := []string{"run", "--rm", "-v", outputDir + ":/output:rw"}
	runArgs = append(runArgs, dockerHostArgs...)
	runArgs = append(runArgs, dockerImage("CHEESEWAF_SQLMAP_DOCKER_IMAGE", defaultSQLMapDockerImage))
	runArgs = append(runArgs, args...)

	return executeSuiteCommand(ctx, suiteCommand{
		Name:    "sqlmap",
		Tool:    "docker",
		Target:  target,
		Args:    runArgs,
		Timeout: opts.ToolTimeout,
	}, classifySQLMapResult(opts, target, append([]string{"docker"}, runArgs...), outputDir))
}

func sqlmapArgs(target, outputDir string) []string {
	args := []string{
		"--batch",
		"--random-agent",
		"--ignore-redirects",
		"--level=1",
		"--risk=1",
		"--threads=1",
		"--timeout=10",
		"--retries=0",
		"--output-dir",
		outputDir,
		"--purge",
		"-u",
		target,
	}
	if strings.HasPrefix(strings.ToLower(target), "https://") {
		args = append(args, "--force-ssl")
	}
	return args
}

func classifySQLMapResult(opts options, target string, command []string, artifact string) func(string, int, error) suiteResult {
	return func(output string, exitCode int, err error) suiteResult {
		status, findings := classifySQLMapStatus(output, exitCode)
		return suiteResult{
			Name:       "sqlmap",
			Tool:       "sqlmap",
			Target:     target,
			Command:    command,
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteErrorForStatus(status, err),
			Artifact:   artifact,
		}
	}
}

func classifySQLMapStatus(output string, exitCode int) (string, int) {
	lower := strings.ToLower(output)
	if hasSQLMapInjectionEvidence(lower) {
		return "failed", 1
	}
	if exitCode != 0 && !hasSQLMapCleanEvidence(lower) {
		return "warning", 0
	}
	return "passed", 0
}

func hasSQLMapInjectionEvidence(lowerOutput string) bool {
	return strings.Contains(lowerOutput, "identified the following injection point") ||
		strings.Contains(lowerOutput, "identified the following injection points") ||
		strings.Contains(lowerOutput, "parameter:") && strings.Contains(lowerOutput, "payload:") ||
		strings.Contains(lowerOutput, "parameter") && strings.Contains(lowerOutput, " is vulnerable")
}

func hasSQLMapCleanEvidence(lowerOutput string) bool {
	cleanPhrases := []string{
		"all tested parameters do not appear to be injectable",
		"does not seem to be injectable",
		"does not appear to be injectable",
		"no injectable parameters",
		"parameter appears to be not injectable",
	}
	for _, phrase := range cleanPhrases {
		if strings.Contains(lowerOutput, phrase) {
			return true
		}
	}
	return false
}

func runXSStrikeSuite(ctx context.Context, opts options, target string) suiteResult {
	args := xsstrikeArgs(target)
	if _, err := lookupExecutable("xsstrike"); err == nil {
		return executeSuiteCommand(ctx, suiteCommand{
			Name:    "xsstrike",
			Tool:    "xsstrike",
			Target:  target,
			Args:    args,
			Timeout: opts.ToolTimeout,
		}, classifyXSStrikeResult(opts, target, append([]string{"xsstrike"}, args...)))
	}
	if _, err := lookupExecutable("docker"); err != nil {
		return suiteResult{
			Name:   "xsstrike",
			Tool:   "xsstrike",
			Target: target,
			Status: "skipped",
			Error:  "xsstrike not found in PATH and docker is not available",
		}
	}
	rewrittenTarget, dockerHostArgs, err := dockerReachableTarget(target)
	if err != nil {
		return suiteResult{Name: "xsstrike", Tool: "xsstrike", Target: target, Status: "failed", Error: err.Error()}
	}
	runArgs := []string{"run", "--rm"}
	runArgs = append(runArgs, dockerHostArgs...)
	runArgs = append(runArgs, dockerImage("CHEESEWAF_XSSTRIKE_DOCKER_IMAGE", defaultXSStrikeDockerImage))
	runArgs = append(runArgs, xsstrikeArgs(rewrittenTarget)...)

	return executeSuiteCommand(ctx, suiteCommand{
		Name:    "xsstrike",
		Tool:    "docker",
		Target:  target,
		Args:    runArgs,
		Timeout: opts.ToolTimeout,
	}, classifyXSStrikeResult(opts, target, append([]string{"docker"}, runArgs...)))
}

func xsstrikeArgs(target string) []string {
	return []string{
		"-u",
		target,
		"--skip",
		"--skip-dom",
		"--timeout",
		"7",
	}
}

func classifyXSStrikeResult(opts options, target string, command []string) func(string, int, error) suiteResult {
	return func(output string, exitCode int, err error) suiteResult {
		status := "passed"
		findings := 0
		lower := strings.ToLower(output)
		if strings.Contains(lower, "vulnerable") ||
			strings.Contains(lower, "possible xss") ||
			strings.Contains(lower, "xss") && strings.Contains(lower, "payload") {
			status = "failed"
			findings = 1
		} else if exitCode != 0 {
			status = "warning"
		}
		return suiteResult{
			Name:       "xsstrike",
			Tool:       "xsstrike",
			Target:     target,
			Command:    command,
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
		}
	}
}

func runNucleiDataSuite(ctx context.Context, opts options, target string) suiteResult {
	return runNucleiSuite(ctx, opts, "nuclei-data", "data", target)
}

func runNucleiAdminSuite(ctx context.Context, opts options, target string) suiteResult {
	return runNucleiSuite(ctx, opts, "nuclei-admin", "admin", target)
}

func runNucleiSuite(ctx context.Context, opts options, name, templateKind, target string) suiteResult {
	templateRoot := strings.TrimSpace(opts.NucleiTemplates)
	if templateRoot == "" {
		templateRoot = "security-validation/nuclei"
	}
	templateDir := filepath.Join(filepath.Clean(templateRoot), templateKind)
	if _, err := os.Stat(templateDir); err != nil {
		return suiteResult{
			Name:   name,
			Tool:   "nuclei",
			Target: target,
			Status: "skipped",
			Error:  fmt.Sprintf("nuclei %s templates unavailable: %v", templateKind, err),
		}
	}

	if _, err := lookupExecutable("nuclei"); err == nil {
		args := nucleiArgs(target, templateDir, opts.Insecure)
		return executeSuiteCommand(ctx, suiteCommand{
			Name:    name,
			Tool:    "nuclei",
			Target:  target,
			Args:    args,
			Timeout: opts.ToolTimeout,
		}, classifyNucleiResult(opts, name, target, append([]string{"nuclei"}, args...)))
	}
	if _, err := lookupExecutable("docker"); err != nil {
		return suiteResult{
			Name:   name,
			Tool:   "nuclei",
			Target: target,
			Status: "skipped",
			Error:  "nuclei not found in PATH and docker is not available",
		}
	}

	absTemplateDir, err := filepath.Abs(templateDir)
	if err != nil {
		return suiteResult{Name: name, Tool: "nuclei", Target: target, Status: "failed", Error: err.Error()}
	}
	rewrittenTarget, dockerHostArgs, err := dockerReachableTarget(target)
	if err != nil {
		return suiteResult{Name: name, Tool: "nuclei", Target: target, Status: "failed", Error: err.Error()}
	}
	args := nucleiArgs(rewrittenTarget, "/templates", opts.Insecure)
	runArgs := []string{"run", "--rm", "-v", absTemplateDir + ":/templates:ro"}
	runArgs = append(runArgs, dockerHostArgs...)
	runArgs = append(runArgs, dockerImage("CHEESEWAF_NUCLEI_DOCKER_IMAGE", defaultNucleiDockerImage))
	runArgs = append(runArgs, args...)

	return executeSuiteCommand(ctx, suiteCommand{
		Name:    name,
		Tool:    "docker",
		Target:  target,
		Args:    runArgs,
		Timeout: opts.ToolTimeout,
	}, classifyNucleiResult(opts, name, target, append([]string{"docker"}, runArgs...)))
}

func nucleiArgs(target, templateDir string, _ bool) []string {
	return []string{
		"-u",
		target,
		"-t",
		templateDir,
		"-jsonl",
		"-silent",
	}
}

func classifyNucleiResult(opts options, name, target string, command []string) func(string, int, error) suiteResult {
	return func(output string, exitCode int, err error) suiteResult {
		findings := countNucleiFindings(output)
		status := "passed"
		switch {
		case findings > 0:
			status = "failed"
		case exitCode != 0:
			status = "warning"
		}
		return suiteResult{
			Name:       name,
			Tool:       "nuclei",
			Target:     target,
			Command:    command,
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
		}
	}
}

func runZAPSuite(ctx context.Context, opts options, target string) suiteResult {
	scriptPath, scriptErr := lookupExecutable("zap-baseline.py")
	_, dockerErr := lookupExecutable("docker")
	if scriptErr != nil && dockerErr != nil {
		return suiteResult{
			Name:   "zap-baseline",
			Tool:   "zap-baseline.py",
			Target: target,
			Status: "skipped",
			Error:  "zap-baseline.py and docker are not available",
		}
	}
	reportDir, err := os.MkdirTemp("", "cheesewaf-zap-*")
	if err != nil {
		return suiteResult{
			Name:   "zap-baseline",
			Tool:   "zap-baseline.py",
			Target: target,
			Status: "failed",
			Error:  err.Error(),
		}
	}
	if err := os.Chmod(reportDir, 0o777); err != nil {
		return suiteResult{
			Name:   "zap-baseline",
			Tool:   "zap-baseline.py",
			Target: target,
			Status: "failed",
			Error:  err.Error(),
		}
	}
	reportFile := filepath.Join(reportDir, "zap-baseline.html")
	if scriptErr == nil {
		args := []string{
			"-t",
			target,
			"-r",
			reportFile,
			"-m",
			"2",
		}
		if strings.HasPrefix(strings.ToLower(target), "https://") || opts.Insecure {
			args = append(args, "-z", "-config connection.sslVerify=false")
		}
		return executeSuiteCommand(ctx, suiteCommand{
			Name:    "zap-baseline",
			Tool:    "zap-baseline.py",
			Target:  target,
			Args:    args,
			Timeout: opts.ToolTimeout,
		}, classifyZAPResult(opts, target, append([]string{scriptPath}, args...), reportFile))
	}

	rewrittenTarget, dockerArgs, rewriteErr := dockerReachableTarget(target)
	if rewriteErr != nil {
		return suiteResult{
			Name:   "zap-baseline",
			Tool:   "zap-baseline.py",
			Target: target,
			Status: "failed",
			Error:  rewriteErr.Error(),
		}
	}

	args := []string{
		"zap-baseline.py",
		"-t",
		rewrittenTarget,
		"-r",
		"zap-baseline.html",
		"-m",
		"2",
	}
	if strings.HasPrefix(strings.ToLower(rewrittenTarget), "https://") || opts.Insecure {
		args = append(args, "-z", "-config connection.sslVerify=false")
	}

	runArgs := []string{"run", "--rm", "-v", reportDir + ":/zap/wrk:rw"}
	runArgs = append(runArgs, dockerArgs...)
	runArgs = append(runArgs, dockerImage("CHEESEWAF_ZAP_DOCKER_IMAGE", defaultZAPDockerImage))
	runArgs = append(runArgs, args...)

	res := executeSuiteCommand(ctx, suiteCommand{
		Name:    "zap-baseline",
		Tool:    "docker",
		Target:  target,
		Args:    runArgs,
		Timeout: opts.ToolTimeout,
	}, classifyZAPResult(opts, target, append([]string{"docker"}, runArgs...), reportFile))
	return res
}

func classifyZAPResult(opts options, target string, command []string, artifact string) func(string, int, error) suiteResult {
	return func(output string, exitCode int, err error) suiteResult {
		status, findings := classifyZAPStatus(output, exitCode)
		return suiteResult{
			Name:       "zap-baseline",
			Tool:       "zap-baseline.py",
			Target:     target,
			Command:    command,
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteErrorForStatus(status, err),
			Artifact:   artifact,
		}
	}
}

func classifyZAPStatus(output string, exitCode int) (string, int) {
	failNew, hasFailNew := zapMetric(output, "FAIL-NEW")
	failInprog, hasFailInprog := zapMetric(output, "FAIL-INPROG")
	findings := failNew + failInprog
	if findings > 0 {
		return "failed", findings
	}
	if exitCode == 0 {
		return "passed", 0
	}
	if exitCode == 2 && hasFailNew && hasFailInprog {
		return "passed", 0
	}
	if exitCode == 2 {
		return "warning", 0
	}
	return "failed", 0
}

func zapMetric(output, name string) (int, bool) {
	fields := strings.Fields(output)
	for i, field := range fields {
		if strings.TrimSuffix(field, ":") != name || i+1 >= len(fields) {
			continue
		}
		value, err := strconv.Atoi(strings.TrimRight(fields[i+1], "\t ,;"))
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

type suiteCommand struct {
	Name    string
	Tool    string
	Target  string
	Args    []string
	Timeout time.Duration
}

func runExternalCommand(ctx context.Context, spec suiteCommand, classify func(output string, exitCode int, err error) suiteResult) suiteResult {
	start := time.Now()
	path, err := lookupExecutable(spec.Tool)
	if err != nil {
		return suiteResult{
			Name:       spec.Name,
			Tool:       spec.Tool,
			Target:     spec.Target,
			Status:     "skipped",
			DurationMS: durationMS(time.Since(start)),
			Error:      fmt.Sprintf("%s not found in PATH", spec.Tool),
		}
	}
	commandCtx := ctx
	var cancel context.CancelFunc
	if spec.Timeout > 0 {
		commandCtx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(commandCtx, path, spec.Args...)
	output, runErr := cmd.CombinedOutput()
	exitCode := 0
	if runErr != nil {
		switch e := runErr.(type) {
		case *exec.ExitError:
			exitCode = e.ExitCode()
		default:
			exitCode = 1
		}
	}
	result := classify(string(output), exitCode, runErr)
	result.DurationMS = durationMS(time.Since(start))
	if len(result.Command) == 0 {
		result.Command = append([]string{path}, spec.Args...)
	}
	if result.Name == "" {
		result.Name = spec.Name
	}
	if result.Tool == "" {
		result.Tool = spec.Tool
	}
	if result.Target == "" {
		result.Target = spec.Target
	}
	return result
}

func dockerReachableTarget(raw string) (string, []string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", nil, err
	}
	if parsed.Host == "" {
		return "", nil, fmt.Errorf("invalid target %q", raw)
	}
	hostname := parsed.Hostname()
	if hostname != "127.0.0.1" && hostname != "localhost" {
		return raw, nil, nil
	}
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort("host.docker.internal", port)
	} else {
		parsed.Host = "host.docker.internal"
	}
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	return parsed.String(), args, nil
}

func dockerImage(envName, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
		return value
	}
	return fallback
}

func trimSuiteOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}
	const limit = 8192
	if len(output) <= limit {
		return output
	}
	return output[:limit] + "\n...<truncated>"
}

func classifySuiteError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func classifySuiteErrorForStatus(status string, err error) string {
	if status == "passed" {
		return ""
	}
	return classifySuiteError(err)
}

func countNucleiFindings(output string) int {
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "{") {
			count++
		}
	}
	return count
}
