package duckdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// maxStderrBytes caps how much child stderr is kept for error messages. A
// failing DuckDB process that loops on a bad file must not grow the parent
// heap while it fails.
const maxStderrBytes = 8 << 10

// errCLIOutputTooLarge marks a child that produced more than the job limit.
// Callers distinguish it from execution failures to report the bound.
var errCLIOutputTooLarge = errors.New("duckdb output exceeds")

// Executor runs one already-validated SQL statement and returns JSON rows.
//
// maxBytes bounds the returned payload. It must be enforced while the child
// runs, not only after it exits: buffering an unbounded stdout first defeats
// the limit. An executor that reads more than maxBytes must fail with an
// "exceeds %d bytes" style error instead of returning the oversized payload.
type Executor interface {
	Query(ctx context.Context, sql string, maxBytes int) ([]byte, error)
}

// CLIExecutor invokes a host-provided DuckDB CLI in read-only mode. The CRP
// never carries this binary.
type CLIExecutor struct {
	Binary  string
	Timeout time.Duration
}

func (e *CLIExecutor) Query(ctx context.Context, sql string, maxBytes int) ([]byte, error) {
	binary := e.Binary
	if binary == "" {
		binary = "duckdb"
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
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
	stderr := &cappedBuffer{max: maxStderrBytes}
	command.Stderr = stderr
	// Bound stdout while the child runs and let WaitDelay bound the leftover
	// pipe wait: a descendant that keeps an inherited stdout open must not
	// delay completion past the delay.
	output := &boundedCLIOutput{max: maxBytes, cancel: cancel}
	command.Stdout = output
	command.WaitDelay = 2 * time.Second
	runErr := command.Run()
	if output.excess {
		return nil, fmt.Errorf("%w %d bytes", errCLIOutputTooLarge, maxBytes)
	}
	if runErr != nil {
		// A killed or timed-out child reports the signal, not the deadline.
		if runContext.Err() != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("duckdb query timed out after %s", timeout)
		}
		if errors.Is(runErr, exec.ErrWaitDelay) {
			return nil, fmt.Errorf("duckdb output pipe did not close: %w", runErr)
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			if message := strings.TrimSpace(stderr.String()); message != "" {
				return nil, fmt.Errorf("duckdb failed: %s", message)
			}
		}
		return nil, fmt.Errorf("duckdb failed: %w", runErr)
	}
	return output.buffer.Bytes(), nil
}

// boundedCLIOutput caps child output while it is produced and cancels the run
// once the limit is crossed, so an unbounded stream never reaches memory.
type boundedCLIOutput struct {
	buffer bytes.Buffer
	max    int
	cancel context.CancelFunc
	excess bool
}

func (w *boundedCLIOutput) Write(p []byte) (int, error) {
	remaining := w.max - w.buffer.Len()
	if len(p) > remaining {
		_, _ = w.buffer.Write(p[:remaining])
		w.excess = true
		w.cancel()
		return remaining, errCLIOutputTooLarge
	}
	return w.buffer.Write(p)
}

// cappedBuffer is an io.Writer that keeps at most max bytes and silently drops
// the remainder, so an unbounded child stream cannot grow the parent heap.
type cappedBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.buf); room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
			b.truncated = true
		} else {
			b.buf = append(b.buf, p...)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	if b.truncated {
		return string(b.buf) + " [truncated]"
	}
	return string(b.buf)
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
	// A hand-built Template can leave MaxBytes zero. Resolve it to the same
	// default CLIExecutor applies, so the limit the executor enforces and the
	// limit checked below are always the same number.
	maxBytes := job.Template.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	paths := make([]string, 0, len(job.SnapshotPaths))
	for _, path := range job.SnapshotPaths {
		paths = append(paths, "'"+escapeLiteral(path)+"'")
	}
	// LoadTemplate accepts template bodies that start with SELECT *or* WITH, so
	// the body cannot be concatenated after the audit_events CTE: two peer WITH
	// clauses are a syntax error. Wrapping the body in a derived table keeps the
	// audit_events CTE in scope for it, keeps exactly one top-level WITH, and
	// preserves the template's columns and row order (SELECT * over a derived
	// table re-exports the inner SELECT list unchanged). BindWindow has already
	// replaced both positional parameters before this point, so no "?" can leak
	// into the wrapper.
	sql := "WITH audit_events AS (SELECT * FROM read_parquet([" + strings.Join(paths, ",") + "]))\n" +
		"SELECT * FROM (\n" + bound + "\n) AS analysis_result"
	raw, err := r.executor.Query(ctx, sql, maxBytes)
	if err != nil {
		return AnalysisRecord{}, err
	}
	// Defensive re-check for executors that do not honour the streaming cap;
	// CLIExecutor already fails while reading rather than returning the excess.
	if len(raw) > maxBytes {
		return AnalysisRecord{}, fmt.Errorf("%w %d bytes", errCLIOutputTooLarge, maxBytes)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return AnalysisRecord{}, fmt.Errorf("duckdb output is not a JSON array: %w", err)
	}
	if len(rows) > job.Template.MaxRows {
		return AnalysisRecord{}, fmt.Errorf("duckdb output exceeds %d rows", job.Template.MaxRows)
	}
	if len(rows) > 1000 {
		return AnalysisRecord{}, fmt.Errorf("duckdb output exceeds 1000 analysis findings")
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
