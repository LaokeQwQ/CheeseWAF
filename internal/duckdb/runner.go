package duckdb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Executor runs one already-validated SQL statement and returns JSON rows.
type Executor interface {
	Query(context.Context, string) ([]byte, error)
}

// CLIExecutor invokes a host-provided DuckDB CLI in read-only mode. The CRP
// never carries this binary.
type CLIExecutor struct {
	Binary  string
	Timeout time.Duration
}

func (e *CLIExecutor) Query(ctx context.Context, sql string) ([]byte, error) {
	binary := e.Binary
	if binary == "" {
		binary = "duckdb"
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	file, err := os.CreateTemp("", "cheesewaf-duckdb-*.sql")
	if err != nil {
		return nil, err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.WriteString(sql); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(runContext, binary, "--readonly", "-json", "-f", name)
	output, err := command.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("duckdb failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	return output, nil
}

// Job is the immutable input to one analysis run.
type Job struct {
	SnapshotRef            string
	SnapshotManifestSHA256 string
	SnapshotPaths          []string
	Template               Template
	WindowFrom             time.Time
	WindowTo               time.Time
	EngineVersion          string
	ExecutionProfileRef    string
	ExecutionProfileSHA256 string
	PluginID               string
	PluginVersion          string
}

// Finding is one analysis-record finding.
type Finding struct {
	Code         string   `json:"code"`
	Severity     string   `json:"severity"`
	Count        int      `json:"count"`
	SubjectHash  string   `json:"subject_hash,omitempty"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// AnalysisRecord is a draft analysis-record/v1 without the host integrity
// envelope. The host validates and signs the final object.
type AnalysisRecord struct {
	APIVersion             string    `json:"api_version"`
	RecordID               string    `json:"record_id"`
	PluginID               string    `json:"plugin_id"`
	PluginVersion          string    `json:"plugin_version"`
	SnapshotRef            string    `json:"snapshot_ref"`
	SnapshotManifestSHA256 string    `json:"snapshot_manifest_sha256"`
	QueryTemplateRef       string    `json:"query_template_ref"`
	QueryTemplateSHA256    string    `json:"query_template_sha256"`
	EngineVersion          string    `json:"engine_version"`
	ExecutionProfileRef    string    `json:"execution_profile_ref"`
	ExecutionProfileSHA256 string    `json:"execution_profile_sha256"`
	GeneratedAt            string    `json:"generated_at"`
	Window                 Window    `json:"window"`
	Findings               []Finding `json:"findings"`
	Recommendations        []string  `json:"recommendations"`
}

type Window struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Runner executes one reviewed template against a host-provided snapshot.
type Runner struct {
	executor Executor
	now      func() time.Time
}

func NewRunner(executor Executor) *Runner {
	return &Runner{executor: executor, now: func() time.Time { return time.Now().UTC() }}
}

func (r *Runner) Run(ctx context.Context, job Job) (AnalysisRecord, error) {
	if r == nil || r.executor == nil {
		return AnalysisRecord{}, fmt.Errorf("duckdb executor is required")
	}
	if len(job.SnapshotPaths) == 0 {
		return AnalysisRecord{}, fmt.Errorf("snapshot paths are required")
	}
	from := job.WindowFrom.UTC().Format(time.RFC3339Nano)
	to := job.WindowTo.UTC().Format(time.RFC3339Nano)
	if !job.WindowFrom.Before(job.WindowTo) {
		return AnalysisRecord{}, fmt.Errorf("analysis window is invalid")
	}
	bound, err := BindWindow(job.Template, from, to)
	if err != nil {
		return AnalysisRecord{}, err
	}
	paths := make([]string, 0, len(job.SnapshotPaths))
	for _, path := range job.SnapshotPaths {
		paths = append(paths, "'"+escapeLiteral(path)+"'")
	}
	sql := "WITH audit_events AS (SELECT * FROM read_parquet([" + strings.Join(paths, ",") + "]))\n" + bound
	raw, err := r.executor.Query(ctx, sql)
	if err != nil {
		return AnalysisRecord{}, err
	}
	if len(raw) > job.Template.MaxBytes {
		return AnalysisRecord{}, fmt.Errorf("duckdb output exceeds %d bytes", job.Template.MaxBytes)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return AnalysisRecord{}, fmt.Errorf("duckdb output is not a JSON array: %w", err)
	}
	if len(rows) > job.Template.MaxRows {
		return AnalysisRecord{}, fmt.Errorf("duckdb output exceeds %d rows", job.Template.MaxRows)
	}
	findings := make([]Finding, 0, len(rows))
	for _, row := range rows {
		severity := "info"
		if value, ok := row["severity"].(string); ok && value != "" {
			severity = value
		}
		subject := ""
		if value, ok := row["subject_hash"].(string); ok {
			subject = value
		}
		count := 1
		if value, ok := row["count"].(float64); ok && value > 0 {
			count = int(value)
		}
		findings = append(findings, Finding{
			Code: "duckdb-row", Severity: severity, Count: count, SubjectHash: subject,
			EvidenceRefs: []string{"evidence:duckdb-" + job.SnapshotRef},
		})
	}
	sum := sha256.Sum256([]byte(job.SnapshotRef + "\x00" + job.Template.SHA256 + "\x00" + from + "\x00" + to))
	record := AnalysisRecord{
		APIVersion: "cheesewaf/analysis-record/v1", RecordID: "analysis-" + hex.EncodeToString(sum[:16]),
		PluginID: job.PluginID, PluginVersion: job.PluginVersion,
		SnapshotRef: job.SnapshotRef, SnapshotManifestSHA256: job.SnapshotManifestSHA256,
		QueryTemplateRef: job.Template.ID, QueryTemplateSHA256: job.Template.SHA256,
		EngineVersion: job.EngineVersion, ExecutionProfileRef: job.ExecutionProfileRef,
		ExecutionProfileSHA256: job.ExecutionProfileSHA256,
		GeneratedAt:            r.now().UTC().Format(time.RFC3339Nano),
		Window:                 Window{From: from, To: to}, Findings: findings, Recommendations: []string{"observe"},
	}
	return record, nil
}
