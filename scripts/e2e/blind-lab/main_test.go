package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	security "github.com/LaokeQwQ/CheeseWAF/internal/security"
)

func TestGenerateIsBoundedAndRepeatable(t *testing.T) {
	d1, err := Generate("2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d1)
	d2, err := Generate("2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d2)
	a, _ := os.ReadFile(filepath.Join(d1, "snapshot.jsonl"))
	b, _ := os.ReadFile(filepath.Join(d2, "snapshot.jsonl"))
	if !bytes.Equal(a, b) {
		t.Fatal("snapshot is not repeatable")
	}
	lines := strings.Split(strings.TrimSpace(string(a)), "\n")
	if len(lines) != 4 {
		t.Fatalf("records=%d, want 4", len(lines))
	}
	seen := map[string]bool{}
	classes := map[string]bool{}
	for _, line := range lines {
		var r snapshotRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Deployment == "" || r.Seed == "" || r.Run == "" {
			t.Fatal("missing deployment provenance")
		}
		seen[r.Deployment] = true
		classes[r.ExpectedOracleLabel.Label] = true
		if strings.HasPrefix(r.Request.Target, "http") {
			t.Fatal("absolute target leaked")
		}
		if r.Request.Method == "" || r.Response.StatusCode == 0 || len(r.Response.Body) == 0 {
			t.Fatal("incomplete HTTP transaction")
		}
		if r.ExpectedOracleLabel.Label == "" || r.Assertion == "" {
			t.Fatal("missing oracle")
		}
	}
	if len(seen) != 2 || !classes["benign"] || !classes["attack"] {
		t.Fatalf("deployments/classes=%v/%v", seen, classes)
	}
	manifest, _ := os.ReadFile(filepath.Join(d1, "manifest.json"))
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.RecordCount != 4 || m.SnapshotSHA256 == "" || len(m.Deployments) != 2 {
		t.Fatal("invalid manifest")
	}
	if m.CasesFile != "cases.jsonl" || m.CasesSHA256 == "" || len(m.Grouping) != 4 {
		t.Fatal("grouping/cases metadata missing")
	}
	cases, err := os.ReadFile(filepath.Join(d1, "cases.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	caseLines := strings.Split(strings.TrimSpace(string(cases)), "\n")
	if len(caseLines) != 4 {
		t.Fatalf("plain case records=%d, want 4", len(caseLines))
	}
	for _, line := range caseLines {
		var c security.Case
		if err := json.Unmarshal([]byte(line), &c); err != nil || c.Name == "" || c.Target == "" {
			t.Fatalf("invalid plain case: %v", err)
		}
	}
	eval, err := os.ReadFile(filepath.Join(d1, "evaluation.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, stats, err := security.LoadEvaluationJSONL(bytes.NewReader(eval), security.EvaluationLoadOptions{MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("evaluation validation failed: %v", err)
	}
	if stats.TotalRecords != 4 || len(loaded) != 4 {
		t.Fatalf("evaluation records=%d/%d", stats.TotalRecords, len(loaded))
	}
	if _, _, err := security.LoadEvaluationJSONL(io.LimitReader(bytes.NewReader(eval), 1), security.EvaluationLoadOptions{MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
		t.Fatal("truncated evaluation unexpectedly accepted")
	}
}

func TestRedactionAndBounds(t *testing.T) {
	v, changed, err := redactBody("token=abc&x=1")
	if err != nil || !changed || strings.Contains(v, "abc") {
		t.Fatalf("redaction failed: %q %v %v", v, changed, err)
	}
	v, changed, err = redactBody(`{"nested":{"token":"abc"},"x":1}`)
	if err != nil || !changed || strings.Contains(v, "abc") || !strings.Contains(v, `"token":"[REDACTED]"`) {
		t.Fatalf("quoted JSON redaction failed: %q %v %v", v, changed, err)
	}
	if _, _, err := redactBody(strings.Repeat("x", maxBodyBytes+1)); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestGenerateAtRequiresAnEmptyLocalDirectory(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "snapshot")
	got, err := GenerateAt("2025-01-01T00:00:00Z", out)
	if err != nil {
		t.Fatal(err)
	}
	if got != out {
		t.Fatalf("output directory=%q, want %q", got, out)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatalf("missing manifest: %v", err)
	}
	if _, err := GenerateAt("2025-01-01T00:00:00Z", out); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("non-empty output directory was accepted: %v", err)
	}
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAt("2025-01-01T00:00:00Z", file); err == nil || !strings.Contains(err.Error(), "local directory") {
		t.Fatalf("regular-file output path was accepted: %v", err)
	}
	if _, err := GenerateAt("not-a-time", filepath.Join(root, "invalid-time")); err == nil {
		t.Fatal("invalid timestamp was accepted")
	}
}
