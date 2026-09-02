package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestNewCorpusRequestPreservesValidatedHostAuthority(t *testing.T) {
	tc := security.Case{
		Method: http.MethodGet,
		Target: "http://origin.example.test/telemetry",
		Header: map[string]string{
			" Host ":  "tenant.example.test:8443",
			"X-Trace": "trace-value",
		},
	}
	req, err := newCorpusRequest(tc)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "tenant.example.test:8443" {
		t.Fatalf("request host = %q, want validated authority", req.Host)
	}
	if got := req.Header.Get("Host"); got != "" {
		t.Fatalf("Host must use Request.Host, found duplicate header %q", got)
	}
	if got := req.Header.Get("X-Trace"); got != "trace-value" {
		t.Fatalf("ordinary header was not preserved: %q", got)
	}
}

func TestRunEvaluationSplitWritesAuditableArtifact(t *testing.T) {
	dir := t.TempDir()
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	makeRecord := func(name, source, site, session, target string) security.EvaluationRecord {
		c := security.Case{Name: name, SourceFamily: source, Label: "benign", Method: http.MethodGet, Target: target}
		return security.EvaluationRecord{
			ID: name, Case: c, Source: source, Site: site, Session: session,
			Timestamp: when, Fingerprint: security.CaseFingerprint(c),
		}
	}
	rows := []security.EvaluationRecord{
		makeRecord("one", "source-one", "site-one", "session-one", "/one"),
		makeRecord("two", "source-two", "site-two", "session-two", "/two"),
		makeRecord("three", "source-three", "site-three", "session-three", "/three"),
	}
	corpus := filepath.Join(dir, "evaluation.jsonl")
	file, err := os.Create(corpus)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "split.json")
	writeGovernanceJSON(t, config, security.SplitConfig{Seed: "cli", ValidationFraction: 0.25, BlindFraction: 0.25})
	output := filepath.Join(dir, "split-output.json")
	if err := runContext(context.Background(), options{
		Mode:            "split",
		CorpusPath:      corpus,
		SplitConfigPath: config,
		OutputPath:      output,
		AllowUngoverned: true,
	}); err != nil {
		t.Fatal(err)
	}
	var artifact security.EvaluationSplitArtifact
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Version != "evaluation-split-v1" || artifact.InputRecords != len(rows) || len(artifact.Records) != len(rows) {
		t.Fatalf("unexpected split artifact: %+v", artifact)
	}
	if artifact.AssignmentPolicy != security.EvaluationSplitAssignmentPolicy || !artifact.Summary.Repaired {
		t.Fatalf("split artifact did not expose assignment policy/repair: %+v", artifact)
	}
	if artifact.Summary.Groups != len(rows) {
		t.Fatalf("unexpected split summary: %+v", artifact.Summary)
	}
	if err := security.ValidateEvaluationSplit(artifact.Records); err != nil {
		t.Fatalf("artifact validation failed: %v", err)
	}
}

func TestRunEvaluationSplitRejectsInvalidConfigAndOverlap(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "evaluation.jsonl")
	row := security.EvaluationRecord{
		ID:     "one",
		Case:   security.Case{Name: "one", SourceFamily: "source", Label: "benign", Method: http.MethodGet, Target: "/"},
		Source: "source", Site: "site", Session: "session",
	}
	row.Fingerprint = security.CaseFingerprint(row.Case)
	data, _ := json.Marshal(row)
	if err := os.WriteFile(corpus, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "split.json")
	writeGovernanceJSON(t, config, security.SplitConfig{Seed: "cli"})
	if err := runContext(context.Background(), options{Mode: "split", CorpusPath: corpus, SplitConfigPath: config, OutputPath: corpus}); err == nil || !strings.Contains(err.Error(), "overlaps an input") {
		t.Fatalf("expected output overlap rejection, got %v", err)
	}
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"seed":"x","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContext(context.Background(), options{Mode: "split", CorpusPath: corpus, SplitConfigPath: unknown}); err == nil || !strings.Contains(err.Error(), "parse split config") {
		t.Fatalf("expected strict config rejection, got %v", err)
	}
	if err := runContext(context.Background(), options{
		Mode: "split", CorpusPath: corpus, SplitConfigPath: config,
		GovernanceFormalPath: corpus,
	}); err == nil || !strings.Contains(err.Error(), "governance formal path overlaps another input") {
		t.Fatalf("expected formal/corpus overlap rejection, got %v", err)
	}
}

func TestVerifyGovernanceSourceHashesRejectsUnreferencedChanges(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.jsonl")
	original := []byte(`{"name":"one","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n")
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{{Path: source}},
		InputHashes: map[string]string{source: digestHex(original)},
	}
	if err := verifyGovernanceSourceHashes(context.Background(), manifest); err != nil {
		t.Fatalf("unchanged governance source rejected: %v", err)
	}
	if err := os.WriteFile(source, append(original, []byte(`{"name":"unreferenced","source_family":"unit","label":"benign","method":"GET","target":"/status"}`+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyGovernanceSourceHashes(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "governance source hash mismatch") {
		t.Fatalf("unreferenced source change was accepted: %v", err)
	}
	optional := filepath.Join(dir, "optional.jsonl")
	requiredForOptional := filepath.Join(dir, "required.jsonl")
	if err := os.WriteFile(requiredForOptional, original, 0o600); err != nil {
		t.Fatal(err)
	}
	optionalManifest := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{
			{Path: requiredForOptional},
			{Path: optional, Optional: true},
		},
		InputHashes:     map[string]string{requiredForOptional: digestHex(original)},
		MissingOptional: []string{optional},
	}
	if err := verifyGovernanceSourceHashes(context.Background(), optionalManifest); err != nil {
		t.Fatalf("unchanged missing optional source rejected: %v", err)
	}
	if err := os.WriteFile(optional, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyGovernanceSourceHashes(context.Background(), optionalManifest); err == nil || !strings.Contains(err.Error(), "appeared after the manifest was created") {
		t.Fatalf("newly present optional source was accepted: %v", err)
	}
}

func TestVerifyGovernanceSourceHashesRejectsSingleSymlinkSource(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "source.jsonl")
	alias := filepath.Join(dir, "source-link.jsonl")
	data := []byte("source\n")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	manifest := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{{Path: alias}},
		InputHashes: map[string]string{alias: digestHex(data)},
	}
	if err := verifyGovernanceSourceHashes(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("single symlink source was unexpectedly accepted: %v", err)
	}
}

func TestVerifyGovernedSourceReferencesRejectsUndeclaredPath(t *testing.T) {
	dir := t.TempDir()
	declared := filepath.Join(dir, "declared.jsonl")
	undeclared := filepath.Join(dir, "undeclared.jsonl")
	line := []byte(`{"name":"one","source_family":"unit","label":"benign","method":"GET","target":"/ok"}` + "\n")
	if err := os.WriteFile(declared, line, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(undeclared, line, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{{Path: declared}},
		InputHashes: map[string]string{declared: digestHex(line)},
	}
	record := security.EvaluationRecord{GovernancePath: undeclared}
	if err := verifyGovernedSourceReferences([]security.EvaluationRecord{record}, manifest); err == nil || !strings.Contains(err.Error(), "not a declared governance source") {
		t.Fatalf("undeclared governance path was accepted: %v", err)
	}
}

func TestSameGovernancePathDoesNotCaseFoldDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "source.jsonl")
	upper := filepath.Join(dir, "SOURCE.jsonl")
	if err := os.WriteFile(lower, []byte("lower\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upper, []byte("upper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	infoLower, err := os.Stat(lower)
	if err != nil {
		t.Fatal(err)
	}
	infoUpper, err := os.Stat(upper)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(infoLower, infoUpper) {
		t.Skip("filesystem is case-insensitive")
	}
	if sameGovernancePath(lower, upper) {
		t.Fatal("distinct case-sensitive source files were treated as the same governance path")
	}
}

func TestRunEvaluationSplitRequiresGovernanceByDefault(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "evaluation.jsonl")
	row := security.EvaluationRecord{
		ID: "one", Case: security.Case{Name: "one", SourceFamily: "source", Label: "benign", Method: http.MethodGet, Target: "/"},
		Source: "source", Site: "site", Session: "session",
	}
	row.Fingerprint = security.CaseFingerprint(row.Case)
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpus, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "split.json")
	writeGovernanceJSON(t, config, security.SplitConfig{Seed: "strict"})
	if err := runContext(context.Background(), options{Mode: "split", CorpusPath: corpus, SplitConfigPath: config}); err == nil || !strings.Contains(err.Error(), "governance_path") {
		t.Fatalf("ungoverned split unexpectedly accepted: %v", err)
	}
	if err := runContext(context.Background(), options{Mode: "split", CorpusPath: corpus, SplitConfigPath: config, AllowUngoverned: true}); err != nil {
		t.Fatalf("explicit ungoverned override rejected: %v", err)
	}
}

func TestRunEvaluationSplitRejectsProvenanceMetadataWithUngovernedOverride(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.jsonl")
	request := security.Case{
		Name: "source-case", SourceFamily: "unit", Label: "benign",
		Method: http.MethodGet, Target: "/source",
	}
	sourceLine, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, append(sourceLine, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	splitConfigPath := filepath.Join(dir, "split.json")
	writeGovernanceJSON(t, splitConfigPath, security.SplitConfig{Seed: "provenance-override"})

	baseRecord := security.EvaluationRecord{
		ID: "row", Case: request, Source: "unit", Site: "site", Session: "session",
		Fingerprint: security.CaseFingerprint(request),
	}
	writeCorpus := func(t *testing.T, name string, record security.EvaluationRecord) string {
		t.Helper()
		path := filepath.Join(dir, name)
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	validSourceHash := digestHex(sourceLine)
	for _, tc := range []struct {
		name string
		row  func() security.EvaluationRecord
		want string
	}{
		{
			name: "forged raw hash",
			row: func() security.EvaluationRecord {
				record := baseRecord
				record.GovernancePath = sourcePath
				record.GovernanceLine = 1
				record.RawHash = strings.Repeat("0", sha256.Size*2)
				record.Decision = "auto"
				return record
			},
			want: "governance raw_hash does not match",
		},
		{
			name: "forged path",
			row: func() security.EvaluationRecord {
				record := baseRecord
				record.GovernancePath = filepath.Join(dir, "missing-source.jsonl")
				record.GovernanceLine = 1
				record.RawHash = validSourceHash
				record.Decision = "auto"
				return record
			},
			want: "verify governance provenance",
		},
		{
			name: "partial provenance",
			row: func() security.EvaluationRecord {
				record := baseRecord
				record.GovernancePath = sourcePath
				record.GovernanceLine = 1
				record.RawHash = validSourceHash
				return record
			},
			want: "decision must be auto or approve",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corpusPath := writeCorpus(t, strings.ReplaceAll(tc.name, " ", "-")+".jsonl", tc.row())
			err := runContext(context.Background(), options{
				Mode: "split", CorpusPath: corpusPath, SplitConfigPath: splitConfigPath,
				OutputPath:      filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+"-artifact.json"),
				AllowUngoverned: true,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("provenance metadata was accepted or misclassified: %v", err)
			}
		})
	}

	// A genuinely hand-authored row remains usable with the explicit override.
	ungovernedPath := writeCorpus(t, "hand-authored.jsonl", baseRecord)
	artifactPath := filepath.Join(dir, "hand-authored-artifact.json")
	if err := runContext(context.Background(), options{
		Mode: "split", CorpusPath: ungovernedPath, SplitConfigPath: splitConfigPath,
		OutputPath: artifactPath, AllowUngoverned: true,
	}); err != nil {
		t.Fatalf("pure hand-authored input was rejected: %v", err)
	}
	var artifact security.EvaluationSplitArtifact
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Governed {
		t.Fatal("pure hand-authored input was marked governed")
	}
}

func TestRunEvaluationSplitArtifactEvaluatesOnlySelectedPartition(t *testing.T) {
	dir := t.TempDir()
	validationStart := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	blindStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	makeRecord := func(name, label, category, source string, when time.Time, body string) security.EvaluationRecord {
		c := security.Case{
			Name: name, SourceFamily: source, Label: label, Category: category,
			Method: http.MethodPost, Target: "/submit", Body: body,
		}
		return security.EvaluationRecord{
			ID: name, Case: c, Source: source, Site: "site-" + name,
			Session: "session-" + name, Timestamp: when,
			Fingerprint: security.CaseFingerprint(c),
		}
	}
	rows := []security.EvaluationRecord{
		makeRecord("train-benign", "benign", "", "source-train-b", validationStart.Add(-24*time.Hour), "status=train-benign"),
		makeRecord("train-attack", "attack", "sqli", "source-train-a", validationStart.Add(-12*time.Hour), "id=train-attack' OR '1'='1"),
		makeRecord("validation-benign", "benign", "", "source-validation-b", validationStart.Add(24*time.Hour), "status=validation-benign"),
		makeRecord("validation-attack", "attack", "sqli", "source-validation-a", validationStart.Add(48*time.Hour), "id=validation-attack' OR '1'='1"),
		makeRecord("blind-benign", "benign", "", "source-blind-b", blindStart.Add(24*time.Hour), "status=blind-benign"),
		makeRecord("blind-attack", "attack", "sqli", "source-blind-a", blindStart.Add(48*time.Hour), "id=blind-attack' OR '1'='1"),
	}
	corpus := filepath.Join(dir, "evaluation.jsonl")
	provenance := filepath.Join(dir, "raw-source.jsonl")
	formalSnapshot := filepath.Join(dir, "formal.jsonl")
	file, err := os.Create(corpus)
	if err != nil {
		t.Fatal(err)
	}
	provenanceFile, err := os.Create(provenance)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	formalFile, err := os.Create(formalSnapshot)
	if err != nil {
		_ = file.Close()
		_ = provenanceFile.Close()
		t.Fatal(err)
	}
	for i := range rows {
		row := &rows[i]
		provenanceLine, err := json.Marshal(row.Case)
		if err != nil {
			_ = file.Close()
			_ = provenanceFile.Close()
			_ = formalFile.Close()
			t.Fatal(err)
		}
		if _, err := provenanceFile.Write(append(provenanceLine, '\n')); err != nil {
			_ = file.Close()
			_ = provenanceFile.Close()
			_ = formalFile.Close()
			t.Fatal(err)
		}
		digest := sha256.Sum256(provenanceLine)
		row.GovernancePath = provenance
		row.GovernanceLine = i + 1
		row.RawHash = hex.EncodeToString(digest[:])
		row.Decision = "auto"
		if err := json.NewEncoder(file).Encode(row); err != nil {
			_ = file.Close()
			_ = provenanceFile.Close()
			_ = formalFile.Close()
			t.Fatal(err)
		}
		formalEntry := struct {
			security.Case
			Source      string `json:"governance_source"`
			Path        string `json:"governance_path"`
			Line        int    `json:"governance_line"`
			RawHash     string `json:"raw_hash"`
			Fingerprint string `json:"fingerprint"`
			Decision    string `json:"decision"`
		}{
			Case: row.Case, Source: row.Source, Path: row.GovernancePath,
			Line: row.GovernanceLine, RawHash: row.RawHash,
			Fingerprint: row.Fingerprint, Decision: row.Decision,
		}
		if err := json.NewEncoder(formalFile).Encode(formalEntry); err != nil {
			_ = file.Close()
			_ = provenanceFile.Close()
			_ = formalFile.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		_ = provenanceFile.Close()
		_ = formalFile.Close()
		t.Fatal(err)
	}
	if err := provenanceFile.Close(); err != nil {
		_ = formalFile.Close()
		t.Fatal(err)
	}
	if err := formalFile.Close(); err != nil {
		t.Fatal(err)
	}
	formalBytes, err := os.ReadFile(formalSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	formalDigest := sha256.Sum256(formalBytes)
	provenanceBytes, err := os.ReadFile(provenance)
	if err != nil {
		t.Fatal(err)
	}
	provenanceDigest := sha256.Sum256(provenanceBytes)
	manifest := security.GovernanceManifest{
		Pipeline:     "test-governance",
		Version:      "v1",
		PolicyHash:   strings.Repeat("a", 64),
		ReviewHash:   strings.Repeat("b", 64),
		SourceSpecs:  []security.SourceSpec{{Path: provenance, Name: "raw-source"}},
		InputHashes:  map[string]string{provenance: hex.EncodeToString(provenanceDigest[:])},
		OutputHashes: map[string]string{"formal": hex.EncodeToString(formalDigest[:])},
		Formal:       len(rows),
		ByDecision:   map[string]int{"hard_reject": 0},
	}
	manifestPayload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestPayloadDigest := sha256.Sum256(manifestPayload)
	manifest.ManifestPayloadHash = hex.EncodeToString(manifestPayloadDigest[:])
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "split.json")
	writeGovernanceJSON(t, config, security.SplitConfig{Seed: "time-test", ValidationStart: &validationStart, BlindStart: &blindStart})
	artifactPath := filepath.Join(dir, "split-artifact.json")
	if err := runContext(context.Background(), options{
		Mode: "split", CorpusPath: corpus, SplitConfigPath: config,
		GovernanceManifestPath: manifestPath, OutputPath: artifactPath,
	}); err == nil || !strings.Contains(err.Error(), "--governance-formal is required") {
		t.Fatalf("metadata envelope without formal snapshot unexpectedly accepted: %v", err)
	}
	if err := runContext(context.Background(), options{Mode: "split", CorpusPath: corpus, SplitConfigPath: config, GovernanceManifestPath: manifestPath, GovernanceFormalPath: formalSnapshot, OutputPath: artifactPath}); err != nil {
		t.Fatal(err)
	}
	t.Run("changed governance source is rejected before a new split", func(t *testing.T) {
		defer func() {
			if err := os.WriteFile(provenance, provenanceBytes, 0o600); err != nil {
				t.Errorf("restore governance source: %v", err)
			}
		}()
		f, err := os.OpenFile(provenance, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.Write([]byte(`{"name":"unreferenced","source_family":"unit","label":"benign","method":"GET","target":"/status"}` + "\n"))
		closeErr := f.Close()
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if err := runContext(context.Background(), options{
			Mode: "split", CorpusPath: corpus, SplitConfigPath: config,
			GovernanceManifestPath: manifestPath, GovernanceFormalPath: formalSnapshot,
			OutputPath: filepath.Join(dir, "changed-source-artifact.json"),
		}); err == nil || !strings.Contains(err.Error(), "governance source hash mismatch") {
			t.Fatalf("changed governance source was accepted: %v", err)
		}
	})
	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256(artifactBytes)
	artifactSHA256 := hex.EncodeToString(artifactDigest[:])
	t.Run("governed blind requires the locked artifact hash", func(t *testing.T) {
		if err := runContext(context.Background(), options{
			Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "blind",
		}); err == nil || !strings.Contains(err.Error(), "--expected-artifact-sha256 is required") {
			t.Fatalf("governed blind replay without its expected artifact hash unexpectedly accepted: %v", err)
		}
	})
	t.Run("all governed partitions require the locked artifact hash", func(t *testing.T) {
		if err := runContext(context.Background(), options{
			Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "validation",
		}); err == nil || !strings.Contains(err.Error(), "--expected-artifact-sha256 is required") {
			t.Fatalf("governed validation replay without its expected artifact hash unexpectedly accepted: %v", err)
		}
	})
	t.Run("wrong locked artifact hash is rejected", func(t *testing.T) {
		wrong := strings.Repeat("f", sha256.Size*2)
		if wrong == artifactSHA256 {
			wrong = strings.Repeat("e", sha256.Size*2)
		}
		if err := runContext(context.Background(), options{
			Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "blind",
			ExpectedArtifactSHA256: wrong,
		}); err == nil || !strings.Contains(err.Error(), "split artifact SHA-256 mismatch") {
			t.Fatalf("governed blind replay with the wrong artifact hash unexpectedly accepted: %v", err)
		}
	})
	t.Run("locked artifact hash must be canonical", func(t *testing.T) {
		if err := runContext(context.Background(), options{
			Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "blind",
			ExpectedArtifactSHA256: strings.Repeat("A", sha256.Size*2),
		}); err == nil || !strings.Contains(err.Error(), "lowercase SHA-256") {
			t.Fatalf("non-canonical artifact hash unexpectedly accepted: %v", err)
		}
	})
	t.Run("quality gate requires the locked artifact hash", func(t *testing.T) {
		t.Setenv("FPR_GATE", "100")
		if err := runContext(context.Background(), options{
			Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "validation",
		}); err == nil || !strings.Contains(err.Error(), "--expected-artifact-sha256 is required") {
			t.Fatalf("quality-gated replay without its expected artifact hash unexpectedly accepted: %v", err)
		}
	})
	reportPath := filepath.Join(dir, "blind-report.json")
	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "blind",
		ExpectedArtifactSHA256: artifactSHA256, OutputPath: reportPath, Workers: 2,
	}); err != nil {
		t.Fatal(err)
	}
	var report splitEvaluationReport
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatal(err)
	}
	if report.Split != security.SplitBlind || report.EvaluatedRecords != 2 || report.BenignTotal != 1 || report.AttackTotal != 1 {
		t.Fatalf("unexpected blind report: %+v", report)
	}
	if report.InputRecords != len(rows) || report.Groups != 2 || report.ArtifactSHA256 == "" {
		t.Fatalf("unexpected artifact accounting: %+v", report)
	}
	if report.ManifestSHA256 == "" || report.ManifestPayloadHash == "" || report.FormalSHA256 == "" || report.SplitInputSHA256 == "" {
		t.Fatalf("blind report is missing governance hashes: %+v", report)
	}
	if report.AttackDetected != 1 || report.FalsePositive != 0 || report.TPRPercent != 100 || report.FPRPercent != 0 {
		t.Fatalf("unexpected blind metrics: %+v", report)
	}
	if len(report.Results) != 2 {
		t.Fatalf("evaluate-split returned non-selected results: %d", len(report.Results))
	}
	var artifact security.EvaluationSplitArtifact
	if err := json.Unmarshal(artifactBytes, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Governance == nil || artifact.Governance.InputSHA256 == "" || artifact.Governance.FormalSHA256 == "" {
		t.Fatalf("split artifact is missing governance binding: %+v", artifact.Governance)
	}
	if artifact.RecordsSHA256 == "" {
		t.Fatal("split artifact is missing its ordered records digest")
	}
	if artifact.Governance.InputSHA256 == artifact.Governance.FormalSHA256 {
		t.Fatal("metadata envelope hash unexpectedly equals the formal snapshot hash")
	}
	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: artifactPath, EvaluationSplit: "blind",
	}); err == nil || !strings.Contains(err.Error(), "--governance-manifest is required") {
		t.Fatalf("governed replay without manifest unexpectedly accepted: %v", err)
	}
	replacement := manifest
	replacement.PolicyHash = strings.Repeat("c", 64)
	replacement.ManifestPayloadHash = ""
	replacementPayload, err := json.MarshalIndent(replacement, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	replacementDigest := sha256.Sum256(replacementPayload)
	replacement.ManifestPayloadHash = hex.EncodeToString(replacementDigest[:])
	replacementBytes, err := json.MarshalIndent(replacement, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	replacementPath := filepath.Join(dir, "replacement-manifest.json")
	if err := os.WriteFile(replacementPath, replacementBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: replacementPath, EvaluationSplit: "blind",
		ExpectedArtifactSHA256: artifactSHA256,
	}); err == nil || !strings.Contains(err.Error(), "does not match the split artifact binding") {
		t.Fatalf("replacement governance manifest unexpectedly accepted: %v", err)
	}

	t.Run("reformatted governance manifest is rejected", func(t *testing.T) {
		reformattedBytes, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(reformattedBytes, manifestBytes) {
			t.Fatal("reformatted manifest unexpectedly retained identical serialized bytes")
		}
		var reformatted security.GovernanceManifest
		if err := json.Unmarshal(reformattedBytes, &reformatted); err != nil {
			t.Fatal(err)
		}
		if reformatted.ManifestPayloadHash != manifest.ManifestPayloadHash {
			t.Fatal("reformatting changed the semantic manifest payload hash")
		}
		reformattedPath := filepath.Join(dir, "reformatted-manifest.json")
		if err := os.WriteFile(reformattedPath, reformattedBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runContext(context.Background(), options{
			Mode: "evaluate-split", CorpusPath: artifactPath, GovernanceManifestPath: reformattedPath, EvaluationSplit: "blind",
			ExpectedArtifactSHA256: artifactSHA256,
		}); err == nil || !strings.Contains(err.Error(), "does not match the split artifact binding") {
			t.Fatalf("byte-distinct governance manifest unexpectedly accepted: %v", err)
		}
	})

	t.Run("artifact content tampering is rejected", func(t *testing.T) {
		mutations := []struct {
			name   string
			mutate func([]security.EvaluationRecord, *security.SplitConfig)
		}{
			{name: "name", mutate: func(records []security.EvaluationRecord, _ *security.SplitConfig) {
				for i := range records {
					if records[i].ID == "blind-attack" {
						records[i].Case.Name += "-tampered"
					}
				}
			}},
			{name: "label", mutate: func(records []security.EvaluationRecord, _ *security.SplitConfig) {
				for i := range records {
					if records[i].ID == "blind-attack" {
						records[i].Case.Label = "benign"
					}
				}
			}},
			{name: "rationale", mutate: func(records []security.EvaluationRecord, _ *security.SplitConfig) {
				for i := range records {
					if records[i].ID == "blind-attack" {
						records[i].Case.Rationale = "tampered rationale"
					}
				}
			}},
			{name: "request", mutate: func(records []security.EvaluationRecord, _ *security.SplitConfig) {
				for i := range records {
					if records[i].ID == "blind-attack" {
						records[i].Case.Body += "&tampered=1"
						records[i].Fingerprint = security.CaseFingerprint(records[i].Case)
					}
				}
			}},
			{name: "split", mutate: func(records []security.EvaluationRecord, _ *security.SplitConfig) {
				for i := range records {
					if records[i].ID == "blind-attack" {
						records[i].Timestamp = validationStart.Add(72 * time.Hour)
					}
				}
			}},
			{name: "group", mutate: func(records []security.EvaluationRecord, _ *security.SplitConfig) {
				for i := range records {
					if records[i].ID == "blind-attack" {
						records[i].Site += "-tampered"
					}
				}
			}},
			{name: "assignment", mutate: func(_ []security.EvaluationRecord, cfg *security.SplitConfig) {
				newBlindStart := blindStart.Add(36 * time.Hour)
				cfg.BlindStart = &newBlindStart
			}},
		}
		for _, mutation := range mutations {
			mutation := mutation
			t.Run(mutation.name, func(t *testing.T) {
				var original security.EvaluationSplitArtifact
				if err := json.Unmarshal(artifactBytes, &original); err != nil {
					t.Fatal(err)
				}
				records := make([]security.EvaluationRecord, len(original.Records))
				for i := range original.Records {
					records[i] = original.Records[i].EvaluationRecord
				}
				config := original.Config
				mutation.mutate(records, &config)
				tampered, err := security.BuildEvaluationSplit(records, config)
				if err != nil {
					t.Fatalf("build tampered %s artifact: %v", mutation.name, err)
				}
				tampered.LoadStats = original.LoadStats
				if original.Governance != nil {
					binding := *original.Governance
					tampered.Governance = &binding
				}
				if err := security.ValidateEvaluationSplitArtifact(tampered); err != nil {
					t.Fatalf("tampered %s artifact is not internally valid: %v", mutation.name, err)
				}
				tamperedPath := filepath.Join(dir, "tampered-artifact-"+mutation.name+".json")
				encoded, err := json.MarshalIndent(tampered, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				encoded = append(encoded, '\n')
				if err := os.WriteFile(tamperedPath, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				err = runContext(context.Background(), options{
					Mode: "evaluate-split", CorpusPath: tamperedPath, GovernanceManifestPath: manifestPath, EvaluationSplit: "blind",
					ExpectedArtifactSHA256: artifactSHA256,
				})
				if err == nil || !strings.Contains(err.Error(), "split artifact SHA-256 mismatch") {
					t.Fatalf("artifact %s tampering unexpectedly accepted or misclassified: %v", mutation.name, err)
				}
			})
		}
	})

	tamperedRows := append([]security.EvaluationRecord(nil), rows...)
	tamperedRows[0].Case.Name += "-tampered"
	tamperedCorpus := filepath.Join(dir, "tampered-evaluation.jsonl")
	tamperedFile, err := os.Create(tamperedCorpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range tamperedRows {
		if err := json.NewEncoder(tamperedFile).Encode(row); err != nil {
			_ = tamperedFile.Close()
			t.Fatal(err)
		}
	}
	if err := tamperedFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runContext(context.Background(), options{
		Mode: "split", CorpusPath: tamperedCorpus, SplitConfigPath: config,
		GovernanceManifestPath: manifestPath, GovernanceFormalPath: formalSnapshot,
		OutputPath: filepath.Join(dir, "tampered-split.json"),
	}); err == nil || !strings.Contains(err.Error(), "does not preserve its governance formal identity") {
		t.Fatalf("tampered split envelope unexpectedly accepted: %v", err)
	}
}

func TestRunEvaluationSplitArtifactRejectsRawCorpusAndMissingPartition(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "raw.jsonl")
	row := security.Case{Name: "raw", SourceFamily: "unit", Label: "benign", Method: http.MethodGet, Target: "/"}
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpus, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContext(context.Background(), options{Mode: "evaluate-split", CorpusPath: corpus, EvaluationSplit: "blind"}); err == nil || !strings.Contains(err.Error(), "parse evaluation split artifact") {
		t.Fatalf("raw corpus unexpectedly accepted: %v", err)
	}
	if err := runContext(context.Background(), options{Mode: "evaluate-split", CorpusPath: corpus}); err == nil || !strings.Contains(err.Error(), "evaluation-split") {
		t.Fatalf("missing partition error=%v", err)
	}
	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: corpus, EvaluationSplit: "blind", GovernanceFormalPath: corpus,
	}); err == nil || !strings.Contains(err.Error(), "only supported in split mode") {
		t.Fatalf("evaluate-split silently accepted --governance-formal: %v", err)
	}
}

func TestOpenLocalRegularFileRejectsSymlinkAndAcceptsStableFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openLocalRegularFile(target, "test input")
	if err != nil {
		t.Fatalf("regular file was rejected: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	alias := filepath.Join(dir, "target-link.json")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if file, err := openLocalRegularFile(alias, "test input"); err == nil {
		_ = file.Close()
		t.Fatal("symlinked file was unexpectedly accepted")
	} else if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink rejection was misclassified: %v", err)
	}
}

func TestRunContextRejectsSymlinkCorpusForReplayModes(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "corpus.jsonl")
	alias := filepath.Join(dir, "corpus-link.jsonl")
	line := []byte(`{"name":"benign","source_family":"unit","label":"benign","method":"GET","target":"/"}` + "\n")
	if err := os.WriteFile(target, line, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := runContext(context.Background(), options{
		Mode:       "analyzer",
		CorpusPath: alias,
		Shards:     1,
		Workers:    1,
	}); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink corpus was unexpectedly accepted: %v", err)
	}
}

func TestLoadEvaluationGovernanceBindingRejectsDuplicateAndGrowingManifest(t *testing.T) {
	dir := t.TempDir()
	duplicatePath := filepath.Join(dir, "duplicate-manifest.json")
	if err := os.WriteFile(duplicatePath, []byte(`{"pipeline":"one","pipeline":"two"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEvaluationGovernanceBinding(duplicatePath, strings.Repeat("a", sha256.Size*2), 0); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate governance manifest key unexpectedly accepted: %v", err)
	}
	growingPath := filepath.Join(dir, "growing-manifest.json")
	file, err := os.Create(growingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxEvaluationGovernanceManifestBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEvaluationGovernanceBinding(growingPath, strings.Repeat("a", sha256.Size*2), 0); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized governance manifest unexpectedly accepted: %v", err)
	}
}

func TestLoadEvaluationGovernanceBindingValidatesInputHashCoverage(t *testing.T) {
	dir := t.TempDir()
	baseManifest := func() security.GovernanceManifest {
		return security.GovernanceManifest{
			Pipeline:     "pipeline-v1",
			Version:      "v1",
			PolicyHash:   strings.Repeat("a", 64),
			ReviewHash:   strings.Repeat("b", 64),
			SourceSpecs:  []security.SourceSpec{{Path: "source.jsonl"}},
			InputHashes:  map[string]string{"source.jsonl": strings.Repeat("c", 64)},
			OutputHashes: map[string]string{"formal": strings.Repeat("d", 64)},
			Formal:       1,
			ByDecision:   map[string]int{"hard_reject": 0},
		}
	}
	writeManifest := func(name string, manifest security.GovernanceManifest) string {
		t.Helper()
		manifest.ManifestPayloadHash = ""
		payload, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestPayloadHash = digestHex(payload)
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	validInputHash := strings.Repeat("e", sha256.Size*2)
	for _, tc := range []struct {
		name      string
		manifest  func() security.GovernanceManifest
		wantError string
	}{
		{
			name: "missing map",
			manifest: func() security.GovernanceManifest {
				m := baseManifest()
				m.InputHashes = nil
				return m
			},
			wantError: "input_hashes must contain",
		},
		{
			name: "invalid digest",
			manifest: func() security.GovernanceManifest {
				m := baseManifest()
				m.InputHashes["source.jsonl"] = strings.Repeat("g", sha256.Size*2)
				return m
			},
			wantError: "input hash for \"source.jsonl\" is missing or invalid",
		},
		{
			name: "missing declared source",
			manifest: func() security.GovernanceManifest {
				m := baseManifest()
				m.SourceSpecs = append(m.SourceSpecs, security.SourceSpec{Path: "second.jsonl"})
				return m
			},
			wantError: "missing an input hash for source \"second.jsonl\"",
		},
		{
			name: "duplicate source",
			manifest: func() security.GovernanceManifest {
				m := baseManifest()
				m.SourceSpecs = append(m.SourceSpecs, security.SourceSpec{Path: "source.jsonl"})
				return m
			},
			wantError: "source_specs contains duplicate path \"source.jsonl\"",
		},
		{
			name: "undeclared source",
			manifest: func() security.GovernanceManifest {
				m := baseManifest()
				m.InputHashes["extra.jsonl"] = validInputHash
				return m
			},
			wantError: "input hash for undeclared source \"extra.jsonl\"",
		},
		{
			name: "unknown missing optional",
			manifest: func() security.GovernanceManifest {
				m := baseManifest()
				m.MissingOptional = []string{"optional.jsonl"}
				return m
			},
			wantError: "is not a declared optional source",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifest(tc.name+".json", tc.manifest())
			if _, _, err := loadEvaluationGovernanceBinding(path, strings.Repeat("f", sha256.Size*2), 0); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("manifest validation error=%v, want substring %q", err, tc.wantError)
			}
		})
	}
	optionalPath := writeManifest("optional-missing.json", func() security.GovernanceManifest {
		m := baseManifest()
		m.SourceSpecs = append(m.SourceSpecs, security.SourceSpec{Path: "optional.jsonl", Optional: true})
		m.MissingOptional = []string{"optional.jsonl"}
		return m
	}())
	if _, _, err := loadEvaluationGovernanceBinding(optionalPath, strings.Repeat("f", sha256.Size*2), 0); err != nil {
		t.Fatalf("declared missing optional source rejected: %v", err)
	}
}

func TestValidateGovernanceManifestInputHashesRejectsAliasedPaths(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.jsonl")
	data := []byte("source\n")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := digestHex(data)

	absoluteAlias := filepath.FromSlash(dir + "/nested/../source.jsonl")
	if absoluteAlias == source {
		t.Fatal("test alias unexpectedly collapsed before validation")
	}
	aliased := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{{Path: source}, {Path: absoluteAlias}},
		InputHashes: map[string]string{source: hash, absoluteAlias: hash},
	}
	if err := validateGovernanceManifestInputHashes(aliased); err == nil || !strings.Contains(err.Error(), "duplicate or aliased path") {
		t.Fatalf("relative-path alias was accepted or misclassified: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeAlias, err := filepath.Rel(cwd, source)
	if err != nil {
		// Windows cannot compute a relative path across volumes (the test
		// directory and checkout may live on different drives). The absolute
		// alias above still exercises canonical-path de-duplication; skip only
		// this cross-volume variant when no relative spelling exists.
		t.Logf("skipping relative alias across volumes: %v", err)
	} else if relativeAlias != source {
		relative := security.GovernanceManifest{
			SourceSpecs: []security.SourceSpec{{Path: source}, {Path: relativeAlias}},
			InputHashes: map[string]string{source: hash, relativeAlias: hash},
		}
		if err := validateGovernanceManifestInputHashes(relative); err == nil || !strings.Contains(err.Error(), "duplicate or aliased path") {
			t.Fatalf("relative/absolute alias was accepted or misclassified: %v", err)
		}
	}

	symlink := filepath.Join(dir, "source-link.jsonl")
	if err := os.Symlink(source, symlink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	symlinkManifest := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{{Path: source}, {Path: symlink}},
		InputHashes: map[string]string{source: hash, symlink: hash},
	}
	if err := validateGovernanceManifestInputHashes(symlinkManifest); err == nil || !strings.Contains(err.Error(), "duplicate or aliased path") {
		t.Fatalf("symlink source alias was accepted or misclassified: %v", err)
	}

	undeclaredAlias := security.GovernanceManifest{
		SourceSpecs: []security.SourceSpec{{Path: source}},
		InputHashes: map[string]string{absoluteAlias: hash},
	}
	if err := validateGovernanceManifestInputHashes(undeclaredAlias); err == nil || !strings.Contains(err.Error(), "missing an input hash for source") && !strings.Contains(err.Error(), "undeclared source") {
		t.Fatalf("input_hashes alias was accepted or misclassified: %v", err)
	}

	optional := filepath.Join(dir, "optional.jsonl")
	missingOptionalAlias := security.GovernanceManifest{
		SourceSpecs:     []security.SourceSpec{{Path: source}, {Path: optional, Optional: true}},
		InputHashes:     map[string]string{source: hash},
		MissingOptional: []string{filepath.FromSlash(dir + "/nested/../optional.jsonl")},
	}
	if err := validateGovernanceManifestInputHashes(missingOptionalAlias); err == nil || !strings.Contains(err.Error(), "not a declared optional source") {
		t.Fatalf("missing_optional alias was accepted or misclassified: %v", err)
	}

	validMissingOptional := security.GovernanceManifest{
		SourceSpecs:     []security.SourceSpec{{Path: source}, {Path: optional, Optional: true}},
		InputHashes:     map[string]string{source: hash},
		MissingOptional: []string{optional},
	}
	if err := validateGovernanceManifestInputHashes(validMissingOptional); err != nil {
		t.Fatalf("valid missing optional source was rejected: %v", err)
	}
}

func TestLoadEvaluationSplitConfigRejectsDuplicateGrowingAndSymlink(t *testing.T) {
	dir := t.TempDir()
	duplicatePath := filepath.Join(dir, "duplicate-split.json")
	if err := os.WriteFile(duplicatePath, []byte(`{"seed":"one","seed":"two"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEvaluationSplitConfig(duplicatePath); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate split config key unexpectedly accepted: %v", err)
	}

	growingPath := filepath.Join(dir, "growing-split.json")
	file, err := os.Create(growingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1<<20 + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEvaluationSplitConfig(growingPath); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized split config unexpectedly accepted: %v", err)
	}

	targetPath := filepath.Join(dir, "target-split.json")
	if err := os.WriteFile(targetPath, []byte(`{"seed":"safe"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(dir, "symlink-split.json")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadEvaluationSplitConfig(symlinkPath); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked split config unexpectedly accepted: %v", err)
	}
}

func TestRunEvaluationSplitArtifactRestrictsLegacyUngovernedReplay(t *testing.T) {
	unsetTestEnv(t, "FPR_GATE")
	unsetTestEnv(t, "TPR_GATE")

	dir := t.TempDir()
	validationStart := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	blindStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	makeRecord := func(name, target string, when time.Time) security.EvaluationRecord {
		c := security.Case{
			Name: name, SourceFamily: "unit-" + name, Label: "benign",
			Method: http.MethodGet, Target: target,
		}
		return security.EvaluationRecord{
			ID: name, Case: c, Source: "source-" + name, Site: "site-" + name,
			Session: "session-" + name, Timestamp: when, Fingerprint: security.CaseFingerprint(c),
		}
	}
	records := []security.EvaluationRecord{
		makeRecord("train", "/health", validationStart.Add(-time.Hour)),
		makeRecord("validation", "/status", validationStart.Add(time.Hour)),
		makeRecord("blind", "/about", blindStart.Add(time.Hour)),
	}
	artifact, err := security.BuildEvaluationSplit(records, security.SplitConfig{
		Seed: "legacy-replay", ValidationStart: &validationStart, BlindStart: &blindStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact.AssignmentPolicy = ""
	if artifact.Governed || artifact.Governance != nil || artifact.Summary.Repaired {
		t.Fatalf("expected a legacy ungoverned artifact, got %+v", artifact)
	}
	artifactPath := filepath.Join(dir, "legacy-ungoverned-artifact.json")
	writeGovernanceJSON(t, artifactPath, artifact)
	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256(artifactBytes)
	artifactSHA256 := hex.EncodeToString(artifactDigest[:])

	for _, split := range []string{"train", "validation"} {
		t.Run(split+" without quality gates", func(t *testing.T) {
			if err := runContext(context.Background(), options{
				Mode: "evaluate-split", CorpusPath: artifactPath, EvaluationSplit: split,
				OutputPath: filepath.Join(dir, split+"-report.json"), Workers: 1,
			}); err != nil {
				t.Fatalf("legacy ungoverned %s replay failed: %v", split, err)
			}
		})
	}
	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: artifactPath, EvaluationSplit: "train",
		ExpectedArtifactSHA256: artifactSHA256, OutputPath: filepath.Join(dir, "train-locked-report.json"), Workers: 1,
	}); err != nil {
		t.Fatalf("legacy ungoverned train replay with matching artifact hash failed: %v", err)
	}
	wrongArtifactSHA256 := strings.Repeat("f", sha256.Size*2)
	if wrongArtifactSHA256 == artifactSHA256 {
		wrongArtifactSHA256 = strings.Repeat("e", sha256.Size*2)
	}
	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: artifactPath, EvaluationSplit: "validation",
		ExpectedArtifactSHA256: wrongArtifactSHA256,
	}); err == nil || !strings.Contains(err.Error(), "split artifact SHA-256 mismatch") {
		t.Fatalf("legacy ungoverned validation replay with wrong artifact hash unexpectedly accepted: %v", err)
	}

	if err := runContext(context.Background(), options{
		Mode: "evaluate-split", CorpusPath: artifactPath, EvaluationSplit: "blind", ExpectedArtifactSHA256: "not-a-hash",
	}); err == nil || !strings.Contains(err.Error(), "ungoverned evaluation split artifacts cannot be replayed as blind quality evidence") {
		t.Fatalf("legacy ungoverned blind replay unexpectedly accepted: %v", err)
	}

	for _, tc := range []struct {
		name  string
		gate  string
		split string
	}{
		{name: "FPR gate", gate: "FPR_GATE", split: "train"},
		{name: "TPR gate", gate: "TPR_GATE", split: "validation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.gate, "50")
			if err := runContext(context.Background(), options{
				Mode: "evaluate-split", CorpusPath: artifactPath, EvaluationSplit: tc.split, ExpectedArtifactSHA256: "not-a-hash",
			}); err == nil || !strings.Contains(err.Error(), "ungoverned evaluation split artifacts cannot be replayed as blind quality evidence") {
				t.Fatalf("legacy ungoverned replay with %s unexpectedly accepted: %v", tc.gate, err)
			}
		})
	}
}

func TestExpectedArtifactHashIsRejectedOutsideSplitReplay(t *testing.T) {
	err := runContext(context.Background(), options{
		Mode:                   "analyzer",
		CorpusPath:             filepath.Join(t.TempDir(), "missing.jsonl"),
		ExpectedArtifactSHA256: strings.Repeat("a", sha256.Size*2),
	})
	if err == nil || !strings.Contains(err.Error(), "only supported in evaluate-split mode") {
		t.Fatalf("expected artifact hash accepted outside evaluate-split: %v", err)
	}
}

func TestApplySplitEvaluationGatesRejectsPointEstimate(t *testing.T) {
	t.Setenv("FPR_GATE", "0")
	t.Setenv("FPR_MIN_BENIGN", "1")
	report := &splitEvaluationReport{Split: security.SplitBlind, BenignTotal: 1, FalsePositive: 1, FPRPercent: 100}
	if err := applySplitEvaluationGates(report); err == nil || !strings.Contains(err.Error(), "FPR gate failed") {
		t.Fatalf("gate error=%v", err)
	}
}

func TestApplySplitEvaluationGatesRejectsUnbalancedBlindShape(t *testing.T) {
	t.Setenv("FPR_GATE", "0.8")
	report := &splitEvaluationReport{
		Split: security.SplitBlind, BenignTotal: 250, BenignClean: 250,
		AttackTotal: 0, Groups: 3,
	}
	if err := applySplitEvaluationGates(report); err == nil || !strings.Contains(err.Error(), "both benign and attack") {
		t.Fatalf("unbalanced blind report unexpectedly accepted: %v", err)
	}
}

func TestApplySplitEvaluationGatesRejectsSingleGroupBlindShape(t *testing.T) {
	t.Setenv("FPR_GATE", "0.8")
	t.Setenv("TPR_GATE", "99")
	report := &splitEvaluationReport{
		Split: security.SplitBlind, BenignTotal: 250, BenignClean: 250,
		AttackTotal: 10000, AttackDetected: 10000, TPRPercent: 100,
		Groups: 1,
	}
	if err := applySplitEvaluationGates(report); err == nil || !strings.Contains(err.Error(), "independent groups") {
		t.Fatalf("single-group blind report unexpectedly accepted: %v", err)
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

func TestLoadGovernanceConfigRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	dir := t.TempDir()
	duplicate := filepath.Join(dir, "duplicate.json")
	if err := os.WriteFile(duplicate, []byte(`{"sources":[],"sources":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGovernanceConfig(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate governance config key unexpectedly accepted: %v", err)
	}

	invalidUTF8 := filepath.Join(dir, "invalid-utf8.json")
	if err := os.WriteFile(invalidUTF8, []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGovernanceConfig(invalidUTF8); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("invalid UTF-8 governance config unexpectedly accepted: %v", err)
	}

	deep := filepath.Join(dir, "deep.json")
	depth := security.DefaultEvaluationArtifactMaxDepth + 2
	deepJSON := strings.Repeat("[", depth) + "null" + strings.Repeat("]", depth)
	if err := os.WriteFile(deep, []byte(deepJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGovernanceConfig(deep); err == nil || !strings.Contains(err.Error(), "nesting limit exceeded") {
		t.Fatalf("deeply nested governance config unexpectedly accepted: %v", err)
	}

	oversized := filepath.Join(dir, "oversized.json")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxGovernanceConfigBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGovernanceConfig(oversized); err == nil || !strings.Contains(err.Error(), "governance config exceeds") {
		t.Fatalf("oversized governance config unexpectedly accepted: %v", err)
	}

	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadGovernanceConfig(symlink); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked governance config unexpectedly accepted: %v", err)
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

func unsetTestEnv(t *testing.T, key string) {
	t.Helper()
	value, ok := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, value)
			return
		}
		_ = os.Unsetenv(key)
	})
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

func TestRunRejectsOverlongCorpusRecords(t *testing.T) {
	t.Setenv("CHEESEWAF_CORPUS_MAX_LINE_BYTES", "64")
	corpus := writeCorpus(t, strings.Repeat("x", 128)+"\n")
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			err := run(options{Mode: "analyzer", CorpusPath: corpus, Shards: 1, Stream: stream})
			if err == nil || !strings.Contains(err.Error(), "overlong record") {
				t.Fatalf("expected overlong corpus rejection, got %v", err)
			}
		})
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

func TestLocalCorpusRequestConstructionWarningsFailAndPreserveDenominators(t *testing.T) {
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
			if err == nil || !strings.Contains(err.Error(), "security corpus validation failed") {
				t.Fatalf("local construction warning should fail validation: %v", err)
			}

			report := readSummary(t, output)
			if report.Total != 2 || report.Warnings != 2 || report.Failures != 2 || report.BenignTotal != 2 || report.BenignClean != 0 {
				t.Fatalf("unexpected local construction summary: %+v", report)
			}
			for _, res := range report.Results {
				if !res.Warning || res.Passed || res.Error == "" {
					t.Fatalf("unexpected local construction result: %+v", res)
				}
			}
		})
	}
}

func TestStreamRequestConstructionWarningsFailAndPreserveDenominators(t *testing.T) {
	corpus := writeCorpus(t,
		`{"name":"bad-benign","source_family":"unit","label":"benign","method":"GET\\nBAD","target":"/ok"}`+"\n"+
			`{"name":"bad-attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"%gh"}`+"\n",
	)
	output := filepath.Join(t.TempDir(), "results.ndjson")
	err := run(options{Mode: "analyzer", CorpusPath: corpus, OutputPath: output, Stream: true, Shards: 1})
	if err == nil || !strings.Contains(err.Error(), "security corpus validation failed") {
		t.Fatalf("stream warning should fail validation: %v", err)
	}

	report := readSummary(t, output+".summary.json")
	if report.Warnings != 2 || report.Failures != 2 || report.BenignTotal != 1 || report.AttackTotal != 1 || report.AttackMissed != 1 || report.BenignClean != 0 {
		t.Fatalf("unexpected streamed warning summary: %+v", report)
	}
	if len(report.Results) != 0 {
		t.Fatalf("stream summary should not collect per-case results: %+v", report.Results)
	}
	lines, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var results []result
	for _, line := range strings.Split(strings.TrimSpace(string(lines)), "\n") {
		var res result
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			t.Fatalf("invalid streamed result: %v", err)
		}
		results = append(results, res)
	}
	for _, res := range results {
		if !res.Warning || res.Passed || res.Error == "" {
			t.Fatalf("unexpected streamed warning result: %+v", res)
		}
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
