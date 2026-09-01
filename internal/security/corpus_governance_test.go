package security

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// governTmp builds a governance config over the given sources and runs it.
func governTmp(t *testing.T, cfg GovernanceConfig) (GovernanceReport, string) {
	t.Helper()
	dir := t.TempDir()
	cfg.FormalPath = filepath.Join(dir, "formal.jsonl")
	cfg.QuarantinePath = filepath.Join(dir, "quarantine.jsonl")
	cfg.ManifestPath = filepath.Join(dir, "manifest.json")
	rep, err := RunGovernance(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunGovernance: %v", err)
	}
	return rep, dir
}

func writeSource(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return p
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func writeGzipSource(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.jsonl.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create gzip source: %v", err)
	}
	gz := gzip.NewWriter(f)
	if _, err := io.WriteString(gz, strings.Join(lines, "\n")+"\n"); err != nil {
		_ = gz.Close()
		_ = f.Close()
		t.Fatalf("write gzip source: %v", err)
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		t.Fatalf("close gzip source: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close gzip file: %v", err)
	}
	return p
}

const (
	attackLine = `{"name":"a1","source_family":"t","label":"attack","category":"sqli","method":"GET","target":"/x?q=1'+or+1=1--","body":""}`
	benignLine = `{"name":"b1","source_family":"t","label":"benign","method":"GET","target":"/home","body":""}`
)

func allowedSource(path string) SourceSpec {
	return SourceSpec{Path: path, Name: "t", DefaultTruth: "attack", License: "repository-curated", Access: "local-file"}
}

// Sources that are not explicitly eligible for formal output stay isolated,
// regardless of whether an otherwise clean row could be auto-selected.
func TestGovernanceSourcesNotAllowedFormalStayQuarantined(t *testing.T) {
	p := writeSource(t, attackLine, benignLine)
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{allowedSource(p)}})
	if got := rep.Manifest.Formal; got != 0 {
		t.Errorf("formal = %d, want 0: unreviewed rows must not be admitted", got)
	}
	if got := rep.Manifest.Quarantine; got != 2 {
		t.Errorf("quarantine = %d, want 2", got)
	}
	if got := rep.Manifest.ByReason["review_required"]; got != 2 {
		t.Errorf("review_required = %d, want 2", got)
	}
}

// TestGovernanceApprovePromotesRow checks the happy path: an approving review
// for the row's exact fingerprint moves it to formal.
func TestGovernanceApprovePromotesRow(t *testing.T) {
	p := writeSource(t, attackLine)
	src := allowedSource(p)
	src.AllowFormal = true

	// Fingerprint the row the same way the pipeline will, so the review matches.
	probe, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{allowedSource(p)}})
	if len(probe.Quarantine) == 0 {
		t.Fatal("expected the row in quarantine before review")
	}
	fp := semanticFingerprint(probe.Quarantine[0])

	rep, _ := governTmp(t, GovernanceConfig{
		Sources: []SourceSpec{src},
		Reviews: []ReviewEntry{{Fingerprint: fp, RuleVersion: "v1", Decision: "approve", Reviewer: "tester"}},
	})
	if got := rep.Manifest.Formal; got != 1 {
		t.Fatalf("formal = %d, want 1 after approval", got)
	}
	if got := rep.Manifest.ReviewApproved; got != 1 {
		t.Errorf("review_approved = %d, want 1", got)
	}
}

// TestGovernanceHardRejectSurvivesApproval pins that a hard finding cannot be
// reviewed into formal. Approval authorises reviewable findings only.
func TestGovernanceConflictingReviewsFail(t *testing.T) {
	p := writeSource(t, attackLine)
	src := allowedSource(p)
	src.AllowFormal = true

	probe, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{allowedSource(p)}})
	if len(probe.Quarantine) == 0 {
		t.Fatal("expected the row in quarantine")
	}
	// A conflicting review for the same fingerprint is itself a hard finding.
	fp := semanticFingerprint(probe.Quarantine[0])
	_, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources: []SourceSpec{src},
		Reviews: []ReviewEntry{
			{Fingerprint: fp, RuleVersion: "v1", Decision: "approve", Reviewer: "reviewer-a"},
			{Fingerprint: fp, RuleVersion: "v1", Decision: "reject", Reviewer: "reviewer-b"},
		},
		FormalPath:     filepath.Join(t.TempDir(), "formal.jsonl"),
		QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"),
		ManifestPath:   filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting decisions") {
		t.Fatalf("conflicting reviews did not fail strictly: %v", err)
	}
}

func TestGovernanceStaleReviewFails(t *testing.T) {
	p := writeSource(t, benignLine)
	_, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources: []SourceSpec{allowedSource(p)},
		Reviews: []ReviewEntry{{
			Fingerprint: strings.Repeat("a", 64),
			RuleVersion: "v1",
			Decision:    "reject",
			Reviewer:    "reviewer",
		}},
		FormalPath:     filepath.Join(t.TempDir(), "formal.jsonl"),
		QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"),
		ManifestPath:   filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown fingerprints") {
		t.Fatalf("stale review did not fail strictly: %v", err)
	}
}

// TestGovernanceRuleVersionMismatch pins that a review recorded under a
// different rule version does not carry: the screening rules changed, so the
// old decision no longer applies.
func TestGovernanceRuleVersionMismatch(t *testing.T) {
	p := writeSource(t, attackLine)
	src := allowedSource(p)
	src.AllowFormal = true

	probe, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{allowedSource(p)}})
	fp := semanticFingerprint(probe.Quarantine[0])

	_, err := RunGovernance(context.Background(), GovernanceConfig{
		RuleVersion:    "v2",
		Sources:        []SourceSpec{src},
		Reviews:        []ReviewEntry{{Fingerprint: fp, RuleVersion: "v1", Decision: "approve", Reviewer: "reviewer"}},
		FormalPath:     filepath.Join(t.TempDir(), "formal.jsonl"),
		QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"),
		ManifestPath:   filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "rule_version") {
		t.Fatalf("rule version mismatch did not fail strictly: %v", err)
	}
}

// TestGovernanceRedactsSecrets covers the PII side. A corpus row carrying a
// bearer token or an Authorization header must never be written out verbatim,
// in either the formal or the quarantine file.
func TestGovernanceRedactsSecrets(t *testing.T) {
	leaky := `{"name":"leak","source_family":"t","label":"attack","category":"sqli","method":"GET","target":"/x?token=abc123","body":"","header":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}}`
	p := writeSource(t, leaky)
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{allowedSource(p)}})

	if got := rep.Manifest.ByReason["secret_detected"]; got != 1 {
		t.Errorf("secret_detected = %d, want 1", got)
	}
	blob := readAll(t, filepath.Join(dir, "quarantine.jsonl")) + readAll(t, filepath.Join(dir, "formal.jsonl"))
	if strings.Contains(blob, "eyJhbGciOiJIUzI1NiJ9") {
		t.Error("raw JWT survived into governance output")
	}
	if strings.Contains(blob, "Bearer eyJ") {
		t.Error("raw bearer token survived into governance output")
	}
	if _, ok := rep.Quarantine[0].Header["Authorization"]; ok {
		t.Error("Authorization header was not stripped")
	}
}

func TestGovernanceSentryDSNIsHardQuarantinedAndRedacted(t *testing.T) {
	dsn := "https://0123456789abcdef0123456789abcdef@o123456.ingest.us.sentry.io/987654"
	line := fmt.Sprintf(`{"name":"sentry","source_family":"telemetry","label":"benign","method":"GET","target":"/health?dsn=%s","body":"telemetry=%s"}`, dsn, dsn)
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})

	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
		t.Fatalf("Sentry DSN escaped hard isolation: %+v", rep.Manifest)
	}
	if rep.Manifest.ByReason["secret_detected"] != 1 {
		t.Fatalf("Sentry DSN was not audited as secret_detected: %+v", rep.Manifest.ByReason)
	}
	blob := readAll(t, filepath.Join(dir, "quarantine.jsonl"))
	if strings.Contains(blob, "0123456789abcdef0123456789abcdef") {
		t.Fatalf("Sentry DSN key survived quarantine output: %s", blob)
	}
	if !strings.Contains(blob, "https://[REDACTED]@o123456.ingest.us.sentry.io/987654") {
		t.Fatalf("Sentry DSN audit shape was not preserved: %s", blob)
	}
}

func TestGovernanceSentryDSNMatcherStaysNarrow(t *testing.T) {
	for _, value := range []string{
		"https://example.com/o123456.ingest.us.sentry.io/987654",
		"https://shortkey@o123456.ingest.us.sentry.io/987654",
		"https://0123456789abcdef0123456789abcdef@o123456.example.com/987654",
	} {
		if sentryDSNRE.MatchString(value) {
			t.Errorf("non-Sentry value matched narrow DSN detector: %q", value)
		}
	}
}

func TestGovernanceSecretHeaderNameIsHardQuarantined(t *testing.T) {
	leaky := `{"name":"leak","source_family":"t","label":"benign","method":"GET","target":"/","header":{"Authorization":"Basic dXNlcjpwYXNz"}}`
	p := writeSource(t, leaky)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})

	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
		t.Fatalf("credential header escaped isolation: %+v", rep.Manifest)
	}
	if rep.Manifest.ByReason["secret_detected"] != 1 {
		t.Fatalf("secret header was not audited: %+v", rep.Manifest.ByReason)
	}
	blob := readAll(t, filepath.Join(dir, "quarantine.jsonl"))
	if strings.Contains(blob, "dXNlcjpwYXNz") || strings.Contains(blob, "Authorization") {
		t.Fatalf("credential header survived quarantine output: %s", blob)
	}
}

func TestGovernanceSensitiveCookieIsHardQuarantinedAndRedacted(t *testing.T) {
	leaky := `{"name":"cookie","source_family":"t","label":"benign","method":"GET","target":"/","header":{"Cookie":"session_id=supersecretvalue; theme=dark"}}`
	p := writeSource(t, leaky)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})

	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
		t.Fatalf("credential cookie escaped isolation: %+v", rep.Manifest)
	}
	if rep.Manifest.ByReason["secret_detected"] != 1 {
		t.Fatalf("credential cookie was not audited: %+v", rep.Manifest.ByReason)
	}
	blob := readAll(t, filepath.Join(dir, "quarantine.jsonl"))
	if strings.Contains(blob, "supersecretvalue") {
		t.Fatalf("credential cookie value survived quarantine output: %s", blob)
	}
	if !strings.Contains(blob, `session_id=[REDACTED]`) || !strings.Contains(blob, `theme=dark`) {
		t.Fatalf("cookie redaction lost its audit shape or safe attributes: %s", blob)
	}
}

func TestGovernanceNonSensitiveCookiePayloadRemainsUsable(t *testing.T) {
	line := `{"name":"cookie-payload","source_family":"t","label":"benign","method":"GET","target":"/","header":{"Cookie":"attack_payload=1%27+OR+1%3D1--; theme=dark"}}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})

	if rep.Manifest.Formal != 1 || rep.Manifest.Quarantine != 0 {
		t.Fatalf("non-credential cookie was over-filtered: %+v", rep.Manifest)
	}
	if got := rep.Formal[0].Header["Cookie"]; got != "attack_payload=1%27+OR+1%3D1--; theme=dark" {
		t.Fatalf("non-credential cookie changed: %q", got)
	}
}

func TestGovernanceSensitiveMetadataIsHardQuarantinedAndRedacted(t *testing.T) {
	type fieldMutation struct {
		name   string
		mutate func(*Case, string)
	}
	fields := []fieldMutation{
		{name: "name", mutate: func(tc *Case, value string) { tc.Name = value }},
		{name: "source_family", mutate: func(tc *Case, value string) { tc.SourceFamily = value }},
		{name: "category", mutate: func(tc *Case, value string) { tc.Category = value; tc.Label = "attack" }},
		{name: "content_type", mutate: func(tc *Case, value string) { tc.ContentType = value }},
		{name: "rationale", mutate: func(tc *Case, value string) { tc.Rationale = value }},
	}
	sensitiveValues := []struct {
		name, value, reason string
	}{
		{name: "email", value: "alice@example.com", reason: "pii_email_detected"},
		{name: "secret", value: "token=abc123", reason: "secret_detected"},
	}
	for _, field := range fields {
		for _, sensitive := range sensitiveValues {
			t.Run(field.name+"/"+sensitive.name, func(t *testing.T) {
				tc := Case{Name: "clean", SourceFamily: "unit", Label: "benign", Method: "GET", Target: "/ok"}
				field.mutate(&tc, sensitive.value)
				encoded, err := json.Marshal(tc)
				if err != nil {
					t.Fatal(err)
				}
				p := writeSource(t, string(encoded))
				src := allowedSource(p)
				src.AllowFormal = true
				rep, dir := governTmp(t, GovernanceConfig{
					Sources: []SourceSpec{src},
					Reviews: []ReviewEntry{{
						Fingerprint: semanticFingerprint(tc),
						RuleVersion: "v1",
						Decision:    "approve",
						Reviewer:    "reviewer",
					}},
				})
				if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
					t.Fatalf("sensitive metadata escaped isolation: %+v", rep.Manifest)
				}
				if rep.Manifest.ByReason[sensitive.reason] != 1 {
					t.Fatalf("missing %s: %+v", sensitive.reason, rep.Manifest.ByReason)
				}
				if strings.Contains(readAll(t, filepath.Join(dir, "quarantine.jsonl")), sensitive.value) {
					t.Fatalf("sensitive value survived output: %q", sensitive.value)
				}
			})
		}
	}
}

func TestGovernanceURIUserinfoIsIsolatedWithoutURLFalsePositives(t *testing.T) {
	cases := []struct {
		name, target string
		wantRedacted bool
	}{
		{name: "userinfo", target: "https://alice:secret@example.test/api", wantRedacted: true},
		{name: "path-colon", target: "/docs/http://example.test/a:b", wantRedacted: false},
		{name: "email", target: "/contact/alice@local", wantRedacted: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Case{Name: tc.name, SourceFamily: "unit", Label: "benign", Method: "GET", Target: tc.target}
			p := writeSource(t, mustJSON(c))
			src := allowedSource(p)
			src.AllowFormal = true
			rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
			if tc.wantRedacted {
				if rep.Manifest.ByReason["secret_detected"] != 1 || rep.Manifest.Quarantine != 1 {
					t.Fatalf("userinfo escaped hard isolation: %+v", rep.Manifest)
				}
				if !strings.Contains(rep.Quarantine[0].Target, "https://[REDACTED]@example.test") {
					t.Fatalf("userinfo was not redacted: %q", rep.Quarantine[0].Target)
				}
			} else if rep.Manifest.Formal != 1 {
				t.Fatalf("ordinary URL/path was over-filtered: %+v", rep.Manifest)
			}
		})
	}
}

func TestGovernanceCSRFHeadersAreSensitiveButCustomHeadersRemain(t *testing.T) {
	for _, name := range []string{"X-XSRF-Token", "X-SF-CSRF-Token", "X-CSRF-Token", "XSRF-Token", "CSRF-Token"} {
		t.Run(name, func(t *testing.T) {
			c := Case{Name: "csrf", SourceFamily: "unit", Label: "benign", Method: "GET", Target: "/", Header: map[string]string{name: "opaque-value"}}
			p := writeSource(t, mustJSON(c))
			src := allowedSource(p)
			src.AllowFormal = true
			rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
			if rep.Manifest.ByReason["secret_detected"] != 1 || rep.Manifest.Quarantine != 1 {
				t.Fatalf("%s escaped isolation: %+v", name, rep.Manifest)
			}
			if _, ok := rep.Quarantine[0].Header[name]; ok {
				t.Fatalf("sensitive header survived sanitization")
			}
		})
	}
	c := Case{Name: "custom", SourceFamily: "unit", Label: "benign", Method: "GET", Target: "/", Header: map[string]string{"X-Feature": "opaque-value"}}
	p := writeSource(t, mustJSON(c))
	src := allowedSource(p)
	src.AllowFormal = true
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.Formal != 1 || rep.Formal[0].Header["X-Feature"] != "opaque-value" {
		t.Fatalf("ordinary custom header was over-filtered: %+v", rep.Manifest)
	}
}

func TestGovernanceManifestCarriesPolicyAndReviewMetadata(t *testing.T) {
	line := `{"name":"pending","source_family":"unit","label":"benign","method":"GET","target":"/download?file={file}"}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	probe, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if len(probe.Quarantine) != 1 {
		t.Fatalf("expected one reviewable row, got %+v", probe.Manifest)
	}
	fp := semanticFingerprint(probe.Quarantine[0])
	review := ReviewEntry{
		Fingerprint: fp,
		RuleVersion: "v1",
		Decision:    "approve",
		Reviewer:    "reviewer",
		Reason:      "manual evidence check",
		ReviewedAt:  "2026-08-31T00:00:00Z",
	}
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}, Reviews: []ReviewEntry{review}})
	if len(rep.Manifest.SourceSpecs) != 1 || rep.Manifest.SourceSpecs[0].Path != p {
		t.Fatalf("source specs missing from manifest: %+v", rep.Manifest.SourceSpecs)
	}
	if !isSHA256(rep.Manifest.PolicyHash) || !isSHA256(rep.Manifest.ReviewHash) {
		t.Fatalf("manifest hashes missing: policy=%q review=%q", rep.Manifest.PolicyHash, rep.Manifest.ReviewHash)
	}
	if len(rep.Manifest.ReviewDecisions) != 1 || rep.Manifest.ReviewDecisions[0].Reason != review.Reason || rep.Manifest.ReviewDecisions[0].ReviewedAt != review.ReviewedAt {
		t.Fatalf("review metadata missing from manifest: %+v", rep.Manifest.ReviewDecisions)
	}
}

func TestGovernanceFormalRowsCarryAuditProvenance(t *testing.T) {
	p := writeSource(t, benignLine)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.Formal != 1 {
		t.Fatalf("expected one clean formal row: %+v", rep.Manifest)
	}
	line := strings.TrimSpace(readAll(t, filepath.Join(dir, "formal.jsonl")))
	var row map[string]any
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"governance_source", "governance_path", "governance_line", "raw_hash", "fingerprint", "decision"} {
		if row[key] == nil || row[key] == "" {
			t.Fatalf("formal row missing %s: %s", key, line)
		}
	}
	if row["decision"] != "auto" {
		t.Fatalf("formal decision = %v, want auto", row["decision"])
	}
}

func TestGovernanceReviewFileHashIsAudited(t *testing.T) {
	p := writeSource(t, benignLine)
	src := allowedSource(p)
	src.AllowFormal = true
	fp := semanticFingerprint(Case{Name: "b1", SourceFamily: "t", Label: "benign", Method: "GET", Target: "/home"})
	reviewPath := filepath.Join(t.TempDir(), "reviews.jsonl")
	reviewLine := fmt.Sprintf(`{"fingerprint":%q,"rule_version":"v1","decision":"approve","reviewer":"reviewer"}`+"\n", fp)
	if err := os.WriteFile(reviewPath, []byte(reviewLine), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}, ReviewPath: reviewPath})
	if !isSHA256(rep.Manifest.ReviewInputHash) {
		t.Fatalf("review input hash missing: %q", rep.Manifest.ReviewInputHash)
	}
	want, err := hashRegularFile(reviewPath)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.ReviewInputHash != want {
		t.Fatalf("review input hash = %s, want %s", rep.Manifest.ReviewInputHash, want)
	}
}

func TestGovernanceRejectsReviewPathOverlappingSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "incoming.jsonl")
	if err := os.WriteFile(source, []byte(benignLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputs := func() (string, string, string) {
		out := t.TempDir()
		return filepath.Join(out, "formal.jsonl"), filepath.Join(out, "quarantine.jsonl"), filepath.Join(out, "manifest.json")
	}
	cases := map[string]string{
		"exact":     source,
		"case-fold": strings.ToUpper(source),
	}
	if alias := filepath.Join(dir, "reviews-alias.jsonl"); os.Symlink(source, alias) == nil {
		cases["symlink"] = alias
	}
	for name, reviewPath := range cases {
		t.Run(name, func(t *testing.T) {
			formal, quarantine, manifest := outputs()
			_, err := RunGovernance(context.Background(), GovernanceConfig{
				Sources:        []SourceSpec{allowedSource(source)},
				ReviewPath:     reviewPath,
				FormalPath:     formal,
				QuarantinePath: quarantine,
				ManifestPath:   manifest,
			})
			if err == nil || !strings.Contains(err.Error(), "review path overlaps input") {
				t.Fatalf("expected review/source overlap error, got %v", err)
			}
		})
	}
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func readAll(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// TestGovernanceRejectsOverlappingPaths prevents the tool from overwriting its
// own inputs — an easy mistake when outputs default to the testdata directory.
func TestGovernanceRejectsOverlappingPaths(t *testing.T) {
	p := writeSource(t, attackLine)
	src := allowedSource(p)
	for name, cfg := range map[string]GovernanceConfig{
		"formal overlaps input":      {Sources: []SourceSpec{src}, FormalPath: p, QuarantinePath: "/tmp/q.jsonl", ManifestPath: "/tmp/m.json"},
		"quarantine overlaps input":  {Sources: []SourceSpec{src}, FormalPath: "/tmp/f.jsonl", QuarantinePath: p, ManifestPath: "/tmp/m.json"},
		"case-folded input overlap":  {Sources: []SourceSpec{src}, FormalPath: strings.ToUpper(p), QuarantinePath: "/tmp/q.jsonl", ManifestPath: "/tmp/m.json"},
		"duplicate outputs":          {Sources: []SourceSpec{src}, FormalPath: "/tmp/same.jsonl", QuarantinePath: "/tmp/same.jsonl", ManifestPath: "/tmp/m.json"},
		"case-folded output overlap": {Sources: []SourceSpec{src}, FormalPath: "/tmp/Corpus.jsonl", QuarantinePath: "/tmp/corpus.jsonl", ManifestPath: "/tmp/m.json"},
		"missing output":             {Sources: []SourceSpec{src}, FormalPath: "", QuarantinePath: "/tmp/q.jsonl", ManifestPath: "/tmp/m.json"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RunGovernance(context.Background(), cfg); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

func TestGovernanceRejectsDuplicateSourceDeclarations(t *testing.T) {
	p := writeSource(t, attackLine)
	variants := []struct {
		name string
		cfg  GovernanceConfig
	}{
		{
			name: "empty source path",
			cfg:  GovernanceConfig{Sources: []SourceSpec{{Name: "missing-path"}}},
		},
		{
			name: "same source list",
			cfg: GovernanceConfig{Sources: []SourceSpec{
				allowedSource(p), allowedSource(p),
			}},
		},
		{
			name: "across source lists",
			cfg: GovernanceConfig{
				Sources:  []SourceSpec{allowedSource(p)},
				Existing: []SourceSpec{allowedSource(filepath.Join(filepath.Dir(p), ".", filepath.Base(p)))},
			},
		},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RunGovernance(context.Background(), withGovernanceOutputs(t, tc.cfg))
			if err == nil {
				t.Fatalf("invalid source declaration was accepted")
			}
			if tc.name == "empty source path" {
				if !strings.Contains(err.Error(), "source path is empty") {
					t.Fatalf("empty source path error=%v", err)
				}
				return
			}
			if !strings.Contains(err.Error(), "duplicate source path") {
				t.Fatalf("duplicate source declaration error=%v", err)
			}
		})
	}

	alias := filepath.Join(t.TempDir(), "source-alias.jsonl")
	if err := os.Symlink(p, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := RunGovernance(context.Background(), withGovernanceOutputs(t, GovernanceConfig{
		Sources:  []SourceSpec{allowedSource(p)},
		Incoming: []SourceSpec{allowedSource(alias)},
	}))
	if err == nil || !strings.Contains(err.Error(), "duplicate source path") {
		t.Fatalf("symlink duplicate source declaration was accepted: %v", err)
	}
}

func withGovernanceOutputs(t *testing.T, cfg GovernanceConfig) GovernanceConfig {
	t.Helper()
	dir := t.TempDir()
	cfg.FormalPath = filepath.Join(dir, "formal.jsonl")
	cfg.QuarantinePath = filepath.Join(dir, "quarantine.jsonl")
	cfg.ManifestPath = filepath.Join(dir, "manifest.json")
	return cfg
}

func TestGovernanceRejectsSymlinkOutputOverlap(t *testing.T) {
	p := writeSource(t, attackLine)
	alias := filepath.Join(t.TempDir(), "formal.jsonl")
	if err := os.Symlink(p, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources: []SourceSpec{allowedSource(p)}, FormalPath: alias,
		QuarantinePath: filepath.Join(t.TempDir(), "q.jsonl"), ManifestPath: filepath.Join(t.TempDir(), "m.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps input") {
		t.Fatalf("symlink output overlap was accepted: %v", err)
	}
}

// TestGovernanceDeduplicatesAcrossSources checks that identical rows from two
// sources collapse to one, and that the duplicate is counted.
func TestGovernanceDeduplicatesAcrossSources(t *testing.T) {
	a := writeSource(t, attackLine)
	b := writeSource(t, attackLine)
	sa, sb := allowedSource(a), allowedSource(b)
	sa.Name, sb.Name = "a", "b"
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{sa, sb}})
	if got := rep.Manifest.Duplicates; got != 1 {
		t.Errorf("duplicates = %d, want 1", got)
	}
	if got := len(rep.Formal) + len(rep.Quarantine); got != 1 {
		t.Errorf("kept = %d, want 1 after dedup", got)
	}
}

// TestGovernanceOptionalMissingSourceIsSkipped covers the git-ignored corpora:
// absent optional files must be skipped, absent required files must fail.
func TestGovernanceOptionalMissingSourceIsSkipped(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.jsonl")
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{{
		Path: missing, Name: "opt", Optional: true, License: "unverified", Access: "local-file",
	}}})
	if got := rep.Manifest.Total; got != 0 {
		t.Errorf("total = %d, want 0 for a skipped optional source", got)
	}
	if got := rep.Manifest.MissingOptional; len(got) != 1 || got[0] != missing {
		t.Errorf("missing_optional = %v, want [%s]", got, missing)
	}
	if _, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources:    []SourceSpec{{Path: missing, Name: "req"}},
		FormalPath: "/tmp/f.jsonl", QuarantinePath: "/tmp/q.jsonl", ManifestPath: "/tmp/m.json",
	}); err == nil {
		t.Error("expected an error for a missing required source")
	}
}

// TestGovernanceManifestIsReproducible pins the integrity property the CI step
// verifies: the same inputs produce byte-identical output hashes, so a manifest
// can be diffed to detect corpus drift.
func TestGovernanceManifestIsReproducible(t *testing.T) {
	p := writeSource(t, attackLine, benignLine)
	src := allowedSource(p)
	run := func() GovernanceManifest {
		rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
		return rep.Manifest
	}
	a, b := run(), run()
	for k, v := range a.InputHashes {
		if b.InputHashes[k] != v {
			t.Errorf("input hash for %s differs across runs", k)
		}
	}
	for k, v := range a.OutputHashes {
		if b.OutputHashes[k] != v {
			t.Errorf("output hash for %s differs across runs: %s vs %s", k, v, b.OutputHashes[k])
		}
	}
	if a.Total != b.Total || a.Formal != b.Formal || a.Quarantine != b.Quarantine {
		t.Errorf("counts differ across runs: %+v vs %+v", a, b)
	}
}

// TestGovernanceFingerprintIsStableAndOrderIndependent guards the dedup key:
// header order must not change the fingerprint, but content must.
func TestGovernanceFingerprintIsStableAndOrderIndependent(t *testing.T) {
	base := Case{Name: "x", Label: "attack", Category: "sqli", Method: "GET", Target: "/a", Body: "b",
		Header: map[string]string{"A": "1", "B": "2"}}
	shuffled := Case{Name: "x", Label: "attack", Category: "sqli", Method: "GET", Target: "/a", Body: "b",
		Header: map[string]string{"B": "2", "A": "1"}}
	if semanticFingerprint(base) != semanticFingerprint(shuffled) {
		t.Error("fingerprint must not depend on header order")
	}
	other := base
	other.Body = "c"
	if semanticFingerprint(base) == semanticFingerprint(other) {
		t.Error("fingerprint must change when the payload changes")
	}
}

func TestGovernanceFingerprintIgnoresLabelsButRetainsSecurityHeaders(t *testing.T) {
	attack := Case{Name: "a", Label: "attack", Category: "sqli", Method: "GET", Target: "/x?b=2&a=1", ContentType: "application/json", Body: "{\"q\": 1}", Header: map[string]string{"Authorization": "Bearer one"}}
	benign := attack
	benign.Name, benign.Label, benign.Category = "b", "benign", ""
	benign.Header = map[string]string{"Authorization": "Bearer two"}
	if semanticFingerprint(attack) == semanticFingerprint(benign) {
		t.Fatal("security header values must distinguish fingerprints")
	}
	noHeader := attack
	noHeader.Header = nil
	if semanticFingerprint(attack) == semanticFingerprint(noHeader) {
		t.Fatal("authorization must not be treated as volatile")
	}
	otherType := attack
	otherType.ContentType = "application/x-www-form-urlencoded"
	if semanticFingerprint(attack) == semanticFingerprint(otherType) {
		t.Fatal("content type must distinguish fingerprints")
	}
	otherWhitespace := attack
	otherWhitespace.Body = "{\"q\":1}"
	if semanticFingerprint(attack) == semanticFingerprint(otherWhitespace) {
		t.Fatal("body whitespace must not be discarded")
	}
	caseFolded := attack
	caseFolded.Header = map[string]string{"authorization": "Bearer one"}
	if semanticFingerprint(attack) != semanticFingerprint(caseFolded) {
		t.Fatal("header names should remain case-insensitive")
	}
	collision := Case{Method: "GET", Target: "/", Header: map[string]string{"X-Test": "one", "x-test": "two"}}
	for i := 0; i < 20; i++ {
		if semanticFingerprint(collision) != semanticFingerprint(collision) {
			t.Fatal("header case collision produced an unstable fingerprint")
		}
	}
}

func TestGovernanceCrossLabelDuplicateIsHardQuarantined(t *testing.T) {
	a := writeSource(t, attackLine)
	b := writeSource(t, `{"name":"b","source_family":"t","label":"benign","method":"GET","target":"/x?q=1'+or+1=1--"}`)
	sa, sb := allowedSource(a), allowedSource(b)
	sa.AllowFormal, sb.AllowFormal = true, true
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{sa, sb}})
	// The conflict is recorded for both the retained canonical row and the
	// duplicate quarantine row, so the reason count is row-level and equals 2.
	if rep.Manifest.Duplicates != 1 || rep.Manifest.ByReason["label_conflict"] != 2 {
		t.Fatalf("unexpected duplicate/conflict counts: %+v", rep.Manifest)
	}
	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 2 {
		t.Fatalf("label conflict must remain quarantined: formal=%d quarantine=%d", rep.Manifest.Formal, rep.Manifest.Quarantine)
	}
}

func TestGovernanceCrossLabelConflictSurvivesCanonicalReplacement(t *testing.T) {
	a := writeSource(t, attackLine)
	b := writeSource(t, `{"name":"b","source_family":"t","label":"benign","method":"GET","target":"/x?q=1'+or+1=1--"}`)
	c := writeSource(t, `{"name":"c","source_family":"t","label":"attack","category":"sqli","method":"GET","target":"/x?q=1'+or+1=1--"}`)
	sa, sb, sc := allowedSource(a), allowedSource(b), allowedSource(c)
	sa.Name, sb.Name, sc.Name = "low-a", "low-b", "preferred"
	sa.AllowFormal, sb.AllowFormal, sc.AllowFormal = false, false, true

	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{sa, sb, sc}})
	if rep.Manifest.Duplicates != 2 {
		t.Fatalf("duplicates = %d, want 2", rep.Manifest.Duplicates)
	}
	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 3 {
		t.Fatalf("replaced conflict group escaped quarantine: formal=%d quarantine=%d", rep.Manifest.Formal, rep.Manifest.Quarantine)
	}
	if rep.Manifest.ByReason["label_conflict"] < 1 {
		t.Fatalf("label conflict disappeared after canonical replacement: %+v", rep.Manifest.ByReason)
	}
}

func TestGovernanceUnknownPayloadTruthIsRejected(t *testing.T) {
	p := writeSource(t, `{"payload":"select a theme","label":"sqli"}`)
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{{Path: p, Name: "unknown", License: "test", Access: "local-file", Optional: true}}})
	if rep.Manifest.Formal != 0 || rep.Manifest.Counts["parse_error"] != 1 {
		t.Fatalf("unknown truth was not rejected: %+v", rep.Manifest)
	}
	if !strings.Contains(readAll(t, filepath.Join(dir, "quarantine.jsonl")), `"kind":"rejected_record"`) {
		t.Fatal("rejected record was not written to quarantine audit output")
	}
}

func TestGovernanceNormalizedShapeCannotFallbackToRaw(t *testing.T) {
	line := []byte(`{"target":"/x","method":"GET","label":"attack","url":"/raw","data":"payload"}`)
	_, err := parseRecord(line, 1, allowedSource("/tmp/source.jsonl"), "source")
	if err == nil || !strings.Contains(err.Error(), "invalid normalized case") {
		t.Fatalf("normalized-shaped invalid row was allowed to fall back: %v", err)
	}
}

func TestGovernanceMalformedRawHeaderIsHardQuarantined(t *testing.T) {
	line := `{"method":"GET","url":"/ok","data":"x=1","headers":"Broken header\nAccept: */*","label":"attack"}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
		t.Fatalf("malformed header loss escaped quarantine: %+v", rep.Manifest)
	}
	if rep.Manifest.ByReason["header_parse_loss"] != 1 || rep.Manifest.ByReason["repaired"] != 1 {
		t.Fatalf("header loss was not audited: %+v", rep.Manifest.ByReason)
	}
	if !strings.Contains(readAll(t, filepath.Join(dir, "quarantine.jsonl")), "header_parse_loss") {
		t.Fatal("quarantine output omitted header loss reason")
	}
}

func TestGovernanceDuplicateRawHeaderIsHardQuarantined(t *testing.T) {
	line := `{"method":"GET","url":"/ok","data":"x=1","headers":"X-Test: one\nx-test: two","label":"benign"}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
		t.Fatalf("duplicate raw header escaped quarantine: %+v", rep.Manifest)
	}
	if rep.Manifest.ByReason["duplicate_header"] != 1 || rep.Manifest.ByReason["header_parse_loss"] != 1 {
		t.Fatalf("duplicate header loss was not audited: %+v", rep.Manifest.ByReason)
	}
	blob := readAll(t, filepath.Join(dir, "quarantine.jsonl"))
	if !strings.Contains(blob, "duplicate_header") || !strings.Contains(blob, "one, two") {
		t.Fatalf("quarantine output lost duplicate-header evidence: %s", blob)
	}
}

func TestGovernanceDuplicateJSONKeyIsHardQuarantined(t *testing.T) {
	line := `{"name":"duplicate-json-key","source_family":"unit","label":"benign","method":"GET","target":"/","header":{"X-Test":"one","X-Test":"two"}}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
		t.Fatalf("duplicate JSON key escaped quarantine: %+v", rep.Manifest)
	}
	if rep.Manifest.ByReason["duplicate_json_key"] != 1 {
		t.Fatalf("duplicate JSON key was not audited: %+v", rep.Manifest.ByReason)
	}
	if !strings.Contains(readAll(t, filepath.Join(dir, "quarantine.jsonl")), "duplicate_json_key") {
		t.Fatal("quarantine output omitted duplicate JSON-key reason")
	}
}

func TestGovernanceCaseInsensitiveDuplicateJSONHeaderKeyIsHardQuarantined(t *testing.T) {
	line := `{"name":"duplicate-json-header-key","source_family":"unit","label":"benign","method":"GET","target":"/","header":{"X-Test":"one","x-test":"two"}}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 || rep.Manifest.ByReason["duplicate_json_key"] != 1 {
		t.Fatalf("case-insensitive duplicate JSON header key escaped quarantine: %+v", rep.Manifest)
	}
}

func TestGovernanceInvalidRequestShapeIsHardQuarantined(t *testing.T) {
	tests := map[string]Case{
		"target control byte": {
			Name: "bad-target", SourceFamily: "unit", Label: "attack", Category: "sqli",
			Method: "GET", Target: "/search?q=select\x1cfrom+users",
		},
		"invalid header name": {
			Name: "bad-header-name", SourceFamily: "unit", Label: "benign",
			Method: "GET", Target: "/", Header: map[string]string{"Bad Header": "value"},
		},
		"invalid header value": {
			Name: "bad-header-value", SourceFamily: "unit", Label: "benign",
			Method: "GET", Target: "/", Header: map[string]string{"X-Test": "value\r\ninjected: yes"},
		},
		"case-insensitive duplicate header": {
			Name: "duplicate-header", SourceFamily: "unit", Label: "benign",
			Method: "GET", Target: "/", Header: map[string]string{"X-Test": "safe", "x-test": "different"},
		},
		"content type field/header collision": {
			Name: "duplicate-content-type", SourceFamily: "unit", Label: "benign",
			Method: "POST", Target: "/", ContentType: "application/json",
			Header: map[string]string{"content-type": "text/plain"},
		},
		"sensitive invalid header name": {
			Name: "sensitive-header-name", SourceFamily: "unit", Label: "benign",
			Method: "GET", Target: "/", Header: map[string]string{"alice@example.com": "value"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			line, err := json.Marshal(tc)
			if err != nil {
				t.Fatal(err)
			}
			p := writeSource(t, string(line))
			src := allowedSource(p)
			src.AllowFormal = true
			rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
			if rep.Manifest.Formal != 0 || rep.Manifest.Quarantine != 1 {
				t.Fatalf("invalid request escaped isolation: %+v", rep.Manifest)
			}
			if rep.Manifest.ByReason["invalid_request_shape"] != 1 {
				t.Fatalf("missing invalid_request_shape reason: %+v", rep.Manifest.ByReason)
			}
			if !strings.Contains(readAll(t, filepath.Join(dir, "quarantine.jsonl")), "invalid_request_shape") {
				t.Fatal("quarantine output omitted invalid request reason")
			}
		})
	}
}

func TestGovernanceResourceBudgetsFailClosed(t *testing.T) {
	p := writeSource(t, benignLine, attackLine)
	_, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources: []SourceSpec{allowedSource(p)}, Limits: GovernanceLimits{MaxRecords: 1},
		FormalPath: filepath.Join(t.TempDir(), "formal.jsonl"), QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"), ManifestPath: filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "max_records") {
		t.Fatalf("record budget did not fail closed: %v", err)
	}

	gzPath := writeGzipSource(t, strings.Repeat("x", 4096))
	_, err = RunGovernance(context.Background(), GovernanceConfig{
		Sources:    []SourceSpec{{Path: gzPath, Name: "gzip", DefaultTruth: "benign", License: "repository-curated", Access: "local-file"}},
		Limits:     GovernanceLimits{MaxDecompressedBytes: 64},
		FormalPath: filepath.Join(t.TempDir(), "formal.jsonl"), QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"), ManifestPath: filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "max_decompressed_bytes") {
		t.Fatalf("decompressed byte budget did not fail closed: %v", err)
	}
}

func TestGovernanceReviewTimestampMustBeRFC3339(t *testing.T) {
	p := writeSource(t, benignLine)
	src := allowedSource(p)
	src.AllowFormal = true
	fp := semanticFingerprint(Case{Name: "b1", SourceFamily: "t", Label: "benign", Method: "GET", Target: "/home"})
	_, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources: []SourceSpec{src}, Reviews: []ReviewEntry{{Fingerprint: fp, RuleVersion: "v1", Decision: "approve", Reviewer: "reviewer", ReviewedAt: "yesterday"}},
		FormalPath: filepath.Join(t.TempDir(), fmt.Sprintf("formal-%d.jsonl", os.Getpid())), QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"), ManifestPath: filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid reviewed_at") {
		t.Fatalf("invalid review timestamp was accepted: %v", err)
	}
}

func TestGovernancePlaceholderAndEmailRequireReview(t *testing.T) {
	line := `{"name":"placeholder","source_family":"t","label":"benign","method":"POST","target":"/upload?file={file}","body":"owner=alice@example.com"}`
	p := writeSource(t, line)
	src := allowedSource(p)
	src.AllowFormal = true
	rep, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	if rep.Manifest.ByReason["placeholder"] != 1 || rep.Manifest.ByReason["pii_email_detected"] != 1 {
		t.Fatalf("screening reasons missing: %+v", rep.Manifest.ByReason)
	}
	if strings.Contains(readAll(t, filepath.Join(dir, "quarantine.jsonl")), "alice@example.com") {
		t.Fatal("email survived quarantine sanitization")
	}
}

func TestGovernanceProvenanceGateCannotBeReviewedOpen(t *testing.T) {
	p := writeSource(t, benignLine)
	src := SourceSpec{Path: p, Name: "missing-provenance", AllowFormal: true}
	probe, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
	fp := semanticFingerprint(probe.Quarantine[0])
	rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}, Reviews: []ReviewEntry{{Fingerprint: fp, RuleVersion: "v1", Decision: "approve", Reviewer: "reviewer"}}})
	if rep.Manifest.Formal != 0 || rep.Manifest.ByReason["source_access_gate"] != 1 {
		t.Fatalf("provenance gate was bypassed: %+v", rep.Manifest)
	}
}

func TestGovernanceRejectsAnonymousReview(t *testing.T) {
	p := writeSource(t, benignLine)
	src := allowedSource(p)
	src.AllowFormal = true
	fp := semanticFingerprint(Case{Name: "b1", SourceFamily: "t", Label: "benign", Method: "GET", Target: "/home"})
	_, err := RunGovernance(context.Background(), GovernanceConfig{
		Sources:        []SourceSpec{src},
		Reviews:        []ReviewEntry{{Fingerprint: fp, RuleVersion: "v1", Decision: "approve"}},
		FormalPath:     filepath.Join(t.TempDir(), "formal.jsonl"),
		QuarantinePath: filepath.Join(t.TempDir(), "quarantine.jsonl"),
		ManifestPath:   filepath.Join(t.TempDir(), "manifest.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "no reviewer") {
		t.Fatalf("anonymous review was not rejected: %v", err)
	}
}

func TestGovernanceRejectsDuplicateReviewJSONKeys(t *testing.T) {
	source := writeSource(t, benignLine)
	for name, line := range map[string]string{
		"exact":     `{"fingerprint":"` + strings.Repeat("a", 64) + `","rule_version":"v1","decision":"approve","decision":"reject","reviewer":"reviewer"}`,
		"case-fold": `{"fingerprint":"` + strings.Repeat("a", 64) + `","rule_version":"v1","decision":"approve","Decision":"reject","reviewer":"reviewer"}`,
	} {
		t.Run(name, func(t *testing.T) {
			reviewPath := filepath.Join(t.TempDir(), "reviews.jsonl")
			if err := os.WriteFile(reviewPath, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			_, err := RunGovernance(context.Background(), GovernanceConfig{
				Sources:        []SourceSpec{allowedSource(source)},
				ReviewPath:     reviewPath,
				FormalPath:     filepath.Join(out, "formal.jsonl"),
				QuarantinePath: filepath.Join(out, "quarantine.jsonl"),
				ManifestPath:   filepath.Join(out, "manifest.json"),
			})
			if err == nil || !strings.Contains(err.Error(), "review file line 1 contains duplicate JSON key") {
				t.Fatalf("expected duplicate review key error, got %v", err)
			}
		})
	}
}

func TestGovernanceRejectsUnverifiedOrRestrictedProvenance(t *testing.T) {
	p := writeSource(t, benignLine)
	for _, src := range []SourceSpec{
		{Path: p, Name: "unknown-license", License: "unverified", Access: "public-direct", AllowFormal: true},
		{Path: p, Name: "invented-license", License: "looks-open", Access: "local-file", AllowFormal: true},
		{Path: p, Name: "restricted-access", License: "MIT", Access: "application-required", AllowFormal: true},
	} {
		rep, _ := governTmp(t, GovernanceConfig{Sources: []SourceSpec{src}})
		if rep.Manifest.Formal != 0 || rep.Manifest.ByReason["source_access_gate"] != 1 {
			t.Fatalf("unverified/restricted source entered formal: %+v", rep.Manifest)
		}
	}
}

// TestGovernanceOutputsAreWrittenAtomically checks that the three artifacts
// exist and that no temp files are left behind by atomicWrite.
func TestGovernanceOutputsAreWrittenAtomically(t *testing.T) {
	p := writeSource(t, attackLine)
	_, dir := governTmp(t, GovernanceConfig{Sources: []SourceSpec{allowedSource(p)}})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
		if strings.HasPrefix(e.Name(), ".governance-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
	for _, want := range []string{"formal.jsonl", "quarantine.jsonl", "manifest.json"} {
		if !names[want] {
			t.Errorf("missing output %s", want)
		}
	}
	m, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed GovernanceManifest
	if err := json.Unmarshal(m, &parsed); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	wantPayloadHash := parsed.ManifestPayloadHash
	parsed.ManifestPayloadHash = ""
	payload, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got := hashBytes(payload); got != wantPayloadHash {
		t.Fatalf("manifest payload hash mismatch: got %s want %s", got, wantPayloadHash)
	}
	for key, name := range map[string]string{"formal": "formal.jsonl", "quarantine": "quarantine.jsonl"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := hashBytes(data); got != parsed.OutputHashes[key] {
			t.Fatalf("%s output hash mismatch: got %s want %s", key, got, parsed.OutputHashes[key])
		}
	}
}

// TestGovernanceContextCancelled makes sure the ctx is honoured on the long
// path, so a hung CI job can be cancelled rather than running to completion.
func TestGovernanceContextCancelled(t *testing.T) {
	p := writeSource(t, attackLine)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RunGovernance(ctx, GovernanceConfig{
		Sources:    []SourceSpec{allowedSource(p)},
		FormalPath: "/tmp/f.jsonl", QuarantinePath: "/tmp/q.jsonl", ManifestPath: "/tmp/m.json",
	})
	if err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}
