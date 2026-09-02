package semantic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// baselineProvenance identifies the exact inputs and source revision behind an
// opt-in external-corpus measurement. The external files are quarantine-only,
// so a report without this binding must never be mistaken for a reproducible
// result. Git metadata is best-effort for copied source trees, while input
// hashes are always attempted and any failure is recorded explicitly.
type baselineProvenance struct {
	GeneratedAt          string                             `json:"generated_at"`
	CodeRevision         string                             `json:"code_revision"`
	GitDirty             bool                               `json:"git_dirty"`
	GitMetadataAvailable bool                               `json:"git_metadata_available"`
	InputFiles           map[string]baselineInputProvenance `json:"input_files"`
	ProvenanceComplete   bool                               `json:"provenance_complete"`
}

type baselineInputProvenance struct {
	Path      string `json:"path"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	HashError string `json:"hash_error,omitempty"`
}

// collectBaselineProvenance hashes every source before an opt-in baseline is
// streamed and captures the repository revision/dirty state at the same
// point. A missing hash is represented in the report rather than silently
// yielding an unbound metric.
func collectBaselineProvenance(paths map[string]string) baselineProvenance {
	provenance := baselineProvenance{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		CodeRevision: "unknown",
		InputFiles:   make(map[string]baselineInputProvenance, len(paths)),
	}

	allInputsHashed := true
	for name, path := range paths {
		input := baselineInputProvenance{Path: filepath.Clean(path)}
		bytesRead, digest, err := hashBaselineInput(path)
		input.Bytes = bytesRead
		input.SHA256 = digest
		if err != nil {
			input.HashError = err.Error()
			allInputsHashed = false
		}
		provenance.InputFiles[name] = input
	}

	revision, dirty, gitAvailable := baselineGitState()
	provenance.CodeRevision = revision
	provenance.GitDirty = dirty
	provenance.GitMetadataAvailable = gitAvailable
	// A clean revision is required: a dirty worktree can contain detector or
	// adapter changes that are not represented by CodeRevision, so the report
	// would not be reproducible from that revision alone.
	provenance.ProvenanceComplete = allInputsHashed && gitAvailable && !dirty
	return provenance
}

func hashBaselineInput(path string) (bytesRead int64, digest string, err error) {
	f, err := openStableCorpusInput(path)
	if err != nil {
		return 0, "", fmt.Errorf("open input: %w", err)
	}
	h := sha256.New()
	bytesRead, readErr := io.Copy(h, f)
	after, statErr := f.Stat()
	pathAfter, pathErr := os.Lstat(path)
	closeErr := f.Close()
	if readErr != nil {
		return bytesRead, "", fmt.Errorf("read input: %w", readErr)
	}
	if statErr != nil {
		return bytesRead, "", fmt.Errorf("stat input: %w", statErr)
	}
	if pathErr != nil {
		return bytesRead, "", fmt.Errorf("lstat input: %w", pathErr)
	}
	if !os.SameFile(after, pathAfter) || after.Size() != pathAfter.Size() {
		return bytesRead, "", fmt.Errorf("input changed while hashing")
	}
	if closeErr != nil {
		return bytesRead, "", fmt.Errorf("close input: %w", closeErr)
	}
	return bytesRead, hex.EncodeToString(h.Sum(nil)), nil
}

func baselineGitState() (revision string, dirty, available bool) {
	revision = "unknown"
	root := baselineRepositoryRoot()
	if root == "" {
		return revision, false, false
	}

	commit, err := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(commit)) == "" {
		return revision, false, false
	}
	revision = strings.TrimSpace(string(commit))
	status, err := exec.Command("git", "-C", root, "status", "--porcelain=v1", "--untracked-files=all").Output()
	if err != nil {
		return revision, false, false
	}
	return revision, strings.TrimSpace(string(status)) != "", true
}

func baselineRepositoryRoot() string {
	starts := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if _, source, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(source))
	}

	seen := make(map[string]struct{}, len(starts))
	for _, start := range starts {
		dir := filepath.Clean(start)
		for {
			if _, done := seen[dir]; !done {
				seen[dir] = struct{}{}
				if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && (info.IsDir() || info.Mode().IsRegular()) {
					return dir
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return ""
}

func TestHashBaselineInputBindsBytesAndDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.jsonl")
	payload := []byte("{\"method\":\"GET\"}\n")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	bytesRead, got, err := hashBaselineInput(path)
	if err != nil {
		t.Fatalf("hashBaselineInput: %v", err)
	}
	want := sha256.Sum256(payload)
	if bytesRead != int64(len(payload)) {
		t.Fatalf("bytesRead=%d, want %d", bytesRead, len(payload))
	}
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("digest=%s, want %s", got, hex.EncodeToString(want[:]))
	}
}

func TestCollectBaselineProvenanceSerializesBindingFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.jsonl")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	provenance := collectBaselineProvenance(map[string]string{"sample": path})
	input, ok := provenance.InputFiles["sample"]
	if !ok {
		t.Fatal("sample input metadata is missing")
	}
	if input.SHA256 == "" || len(input.SHA256) != sha256.Size*2 {
		t.Fatalf("input SHA-256 is not bound: %+v", input)
	}
	if input.Bytes != int64(len("one\ntwo\n")) {
		t.Fatalf("input byte count=%d, want %d", input.Bytes, len("one\ntwo\n"))
	}
	if input.Path != filepath.Clean(path) {
		t.Fatalf("input path=%q, want %q", input.Path, filepath.Clean(path))
	}
	if provenance.GeneratedAt == "" {
		t.Fatal("generated timestamp is missing")
	}

	data, err := json.Marshal(provenance)
	if err != nil {
		t.Fatalf("marshal provenance: %v", err)
	}
	for _, field := range []string{`"generated_at"`, `"code_revision"`, `"git_dirty"`, `"git_metadata_available"`, `"input_files"`, `"provenance_complete"`} {
		if !strings.Contains(string(data), field) {
			t.Errorf("serialized provenance is missing %s: %s", field, data)
		}
	}
}

func TestCollectBaselineProvenanceRecordsHashFailure(t *testing.T) {
	provenance := collectBaselineProvenance(map[string]string{"missing": filepath.Join(t.TempDir(), "missing.jsonl")})
	input := provenance.InputFiles["missing"]
	if input.HashError == "" {
		t.Fatal("missing input hash failure was not recorded")
	}
	if input.SHA256 != "" || provenance.ProvenanceComplete {
		t.Fatalf("incomplete provenance was marked complete: %+v", provenance)
	}
}

func TestBaselineCorpusInputsRejectSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "source.jsonl")
	alias := filepath.Join(dir, "source-link.jsonl")
	if err := os.WriteFile(target, []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := openCorpusFile(alias); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink corpus was unexpectedly accepted: %v", err)
	}
	if _, _, err := hashBaselineInput(alias); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink provenance input was unexpectedly accepted: %v", err)
	}
}

func TestWriteBaselineReportFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "report.json")
	if err := os.WriteFile(target, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeBaselineReportFile(link, []byte("new\n")); err == nil {
		t.Fatal("symlink baseline report path was accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "sentinel\n" {
		t.Fatalf("symlink target was modified: %q", string(data))
	}
}

func TestWriteBaselineReportFileInstallsCompleteDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	data := []byte("{\"complete\":true}\n")
	if err := writeBaselineReportFile(path, data); err != nil {
		t.Fatalf("write baseline report: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline report: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("report contents=%q, want %q", got, data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat baseline report: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestWriteBaselineReportFileReplacesExistingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("seed old report: %v", err)
	}
	if err := writeBaselineReportFile(path, []byte("new\n")); err != nil {
		t.Fatalf("replace baseline report: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced report: %v", err)
	}
	if string(got) != "new\n" {
		t.Fatalf("report contents=%q, want %q", got, "new\\n")
	}
}

func TestExternalBaselineDocumentationDescribesProvenance(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/evaluation-platform.md")
	if err != nil {
		t.Fatalf("read evaluation documentation: %v", err)
	}
	for _, required := range []string{"`provenance`", "`provenance_complete`", "SHA-256", "dirty state"} {
		if !strings.Contains(string(doc), required) {
			t.Errorf("evaluation documentation is missing %q", required)
		}
	}
}
