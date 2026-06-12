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
	"strings"
	"time"
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
	if _, err := exec.LookPath("sqlmap"); err != nil {
		return suiteResult{
			Name:   "sqlmap",
			Tool:   "sqlmap",
			Target: target,
			Status: "skipped",
			Error:  "sqlmap not found in PATH",
		}
	}
	outputDir, err := os.MkdirTemp("", "cheesewaf-sqlmap-*")
	if err != nil {
		return suiteResult{
			Name:   "sqlmap",
			Tool:   "sqlmap",
			Target: target,
			Status: "skipped",
			Error:  err.Error(),
		}
	}
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
		"--purge-output",
		"-u",
		target,
	}
	if strings.HasPrefix(strings.ToLower(target), "https://") {
		args = append(args, "--force-ssl")
	}
	return runExternalCommand(ctx, suiteCommand{
		Name:    "sqlmap",
		Tool:    "sqlmap",
		Target:  target,
		Args:    args,
		Timeout: opts.ToolTimeout,
	}, func(output string, exitCode int, err error) suiteResult {
		status := "passed"
		findings := 0
		lower := strings.ToLower(output)
		if strings.Contains(lower, "identified the following injection point") ||
			strings.Contains(lower, "sql injection") ||
			strings.Contains(lower, "is vulnerable") {
			status = "failed"
			findings = 1
		} else if exitCode != 0 {
			if strings.Contains(lower, "not injectable") ||
				strings.Contains(lower, "no injectable parameters") ||
				strings.Contains(lower, "parameter appears to be not injectable") {
				status = "passed"
			} else {
				status = "warning"
			}
		}
		return suiteResult{
			Name:       "sqlmap",
			Tool:       "sqlmap",
			Target:     target,
			Command:    append([]string{"sqlmap"}, args...),
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
		}
	})
}

func runXSStrikeSuite(ctx context.Context, opts options, target string) suiteResult {
	args := []string{
		"-u",
		target,
		"--skip",
		"--skip-dom",
		"--timeout",
		"7",
	}
	return runExternalCommand(ctx, suiteCommand{
		Name:    "xsstrike",
		Tool:    "xsstrike",
		Target:  target,
		Args:    args,
		Timeout: opts.ToolTimeout,
	}, func(output string, exitCode int, err error) suiteResult {
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
			Command:    append([]string{"xsstrike"}, args...),
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
		}
	})
}

func runNucleiDataSuite(ctx context.Context, opts options, target string) suiteResult {
	templateRoot := strings.TrimSpace(opts.NucleiTemplates)
	if templateRoot == "" {
		templateRoot = "security-validation/nuclei"
	}
	templateDir := filepath.Join(filepath.Clean(templateRoot), "data")
	if _, err := os.Stat(templateDir); err != nil {
		return suiteResult{
			Name:   "nuclei-data",
			Tool:   "nuclei",
			Target: target,
			Status: "skipped",
			Error:  fmt.Sprintf("nuclei templates unavailable: %v", err),
		}
	}
	args := []string{
		"-u",
		target,
		"-t",
		templateDir,
		"-jsonl",
		"-silent",
	}
	if strings.HasPrefix(strings.ToLower(target), "https://") || opts.Insecure {
		args = append(args, "-insecure")
	}
	return runExternalCommand(ctx, suiteCommand{
		Name:    "nuclei-data",
		Tool:    "nuclei",
		Target:  target,
		Args:    args,
		Timeout: opts.ToolTimeout,
	}, func(output string, exitCode int, err error) suiteResult {
		findings := countNucleiFindings(output)
		status := "passed"
		switch {
		case findings > 0:
			status = "failed"
		case exitCode != 0:
			status = "warning"
		}
		return suiteResult{
			Name:       "nuclei-data",
			Tool:       "nuclei",
			Target:     target,
			Command:    append([]string{"nuclei"}, args...),
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
		}
	})
}

func runNucleiAdminSuite(ctx context.Context, opts options, target string) suiteResult {
	templateRoot := strings.TrimSpace(opts.NucleiTemplates)
	if templateRoot == "" {
		templateRoot = "security-validation/nuclei"
	}
	templateDir := filepath.Join(filepath.Clean(templateRoot), "admin")
	if _, err := os.Stat(templateDir); err != nil {
		return suiteResult{
			Name:   "nuclei-admin",
			Tool:   "nuclei",
			Target: target,
			Status: "skipped",
			Error:  fmt.Sprintf("nuclei admin templates unavailable: %v", err),
		}
	}
	args := []string{
		"-u",
		target,
		"-t",
		templateDir,
		"-jsonl",
		"-silent",
	}
	if strings.HasPrefix(strings.ToLower(target), "https://") || opts.Insecure {
		args = append(args, "-insecure")
	}
	return runExternalCommand(ctx, suiteCommand{
		Name:    "nuclei-admin",
		Tool:    "nuclei",
		Target:  target,
		Args:    args,
		Timeout: opts.ToolTimeout,
	}, func(output string, exitCode int, err error) suiteResult {
		findings := countNucleiFindings(output)
		status := "passed"
		switch {
		case findings > 0:
			status = "failed"
		case exitCode != 0:
			status = "warning"
		}
		return suiteResult{
			Name:       "nuclei-admin",
			Tool:       "nuclei",
			Target:     target,
			Command:    append([]string{"nuclei"}, args...),
			Status:     status,
			ExitCode:   exitCode,
			Findings:   findings,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
		}
	})
}

func runZAPSuite(ctx context.Context, opts options, target string) suiteResult {
	scriptPath, scriptErr := exec.LookPath("zap-baseline.py")
	_, dockerErr := exec.LookPath("docker")
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
		return runExternalCommand(ctx, suiteCommand{
			Name:    "zap-baseline",
			Tool:    "zap-baseline.py",
			Target:  target,
			Args:    args,
			Timeout: opts.ToolTimeout,
		}, func(output string, exitCode int, err error) suiteResult {
			status := "passed"
			switch exitCode {
			case 0:
				status = "passed"
			case 2:
				status = "warning"
			default:
				status = "failed"
			}
			return suiteResult{
				Name:       "zap-baseline",
				Tool:       "zap-baseline.py",
				Target:     target,
				Command:    append([]string{scriptPath}, args...),
				Status:     status,
				ExitCode:   exitCode,
				DurationMS: durationMS(opts.ToolTimeout),
				Output:     trimSuiteOutput(output),
				Error:      classifySuiteError(err),
				Artifact:   reportFile,
			}
		})
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
	runArgs = append(runArgs, "ghcr.io/zaproxy/zaproxy:stable")
	runArgs = append(runArgs, args...)

	res := runExternalCommand(ctx, suiteCommand{
		Name:    "zap-baseline",
		Tool:    "docker",
		Target:  target,
		Args:    runArgs,
		Timeout: opts.ToolTimeout,
	}, func(output string, exitCode int, err error) suiteResult {
		status := "passed"
		switch exitCode {
		case 0:
			status = "passed"
		case 2:
			status = "warning"
		default:
			status = "failed"
		}
		return suiteResult{
			Name:       "zap-baseline",
			Tool:       "zap-baseline.py",
			Target:     target,
			Command:    append([]string{"docker"}, runArgs...),
			Status:     status,
			ExitCode:   exitCode,
			DurationMS: durationMS(opts.ToolTimeout),
			Output:     trimSuiteOutput(output),
			Error:      classifySuiteError(err),
			Artifact:   reportFile,
		}
	})
	return res
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
	path, err := exec.LookPath(spec.Tool)
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
	parsed.Host = net.JoinHostPort("host.docker.internal", parsed.Port())
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	return parsed.String(), args, nil
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
