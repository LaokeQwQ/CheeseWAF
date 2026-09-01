package security

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// SourceSpec describes one explicit, local corpus file.
type SourceSpec struct {
	Path         string `json:"path"`
	Name         string `json:"name,omitempty"`
	DefaultTruth string `json:"default_truth,omitempty"`
	License      string `json:"license,omitempty"`
	Access       string `json:"access,omitempty"`
	AllowFormal  bool   `json:"allow_formal,omitempty"`
	Optional     bool   `json:"optional,omitempty"`
}

type ReviewEntry struct {
	Fingerprint string `json:"fingerprint"`
	RuleVersion string `json:"rule_version"`
	Decision    string `json:"decision"`
	Reviewer    string `json:"reviewer,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ReviewedAt  string `json:"reviewed_at,omitempty"`
}

type GovernanceConfig struct {
	Sources         []SourceSpec     `json:"sources,omitempty"`
	Existing        []SourceSpec     `json:"existing,omitempty"`
	Incoming        []SourceSpec     `json:"incoming,omitempty"`
	FormalPath      string           `json:"formal_path"`
	QuarantinePath  string           `json:"quarantine_path"`
	ManifestPath    string           `json:"manifest_path"`
	Reviews         []ReviewEntry    `json:"reviews,omitempty"`
	ReviewPath      string           `json:"review_path,omitempty"`
	RuleVersion     string           `json:"rule_version,omitempty"`
	PipelineVersion string           `json:"pipeline_version,omitempty"`
	Limits          GovernanceLimits `json:"limits,omitempty"`
}

// GovernanceLimits bounds local corpus processing. Defaults are deliberately
// finite so an untrusted compressed input cannot consume unbounded memory,
// disk bandwidth, or CPU merely because it is a local file.
type GovernanceLimits struct {
	MaxRecords           int     `json:"max_records,omitempty"`
	MaxInputBytes        int64   `json:"max_input_bytes,omitempty"`
	MaxDecompressedBytes int64   `json:"max_decompressed_bytes,omitempty"`
	MaxExpansionRatio    float64 `json:"max_expansion_ratio,omitempty"`
}

type GovernanceManifest struct {
	Pipeline            string              `json:"pipeline"`
	Version             string              `json:"version"`
	PolicyHash          string              `json:"policy_hash"`
	ReviewHash          string              `json:"review_hash"`
	ReviewInputHash     string              `json:"review_input_hash,omitempty"`
	SourceSpecs         []SourceSpec        `json:"source_specs"`
	Limits              GovernanceLimits    `json:"limits"`
	ReviewDecisions     []ReviewEntry       `json:"review_decisions,omitempty"`
	InputHashes         map[string]string   `json:"input_hashes"`
	OutputHashes        map[string]string   `json:"output_hashes"`
	Total               int                 `json:"total"`
	Formal              int                 `json:"formal"`
	Quarantine          int                 `json:"quarantine"`
	Counts              map[string]int      `json:"counts"`
	BySource            map[string]int      `json:"by_source"`
	RowsBySource        map[string]int      `json:"rows_by_source"`
	RejectedBySource    map[string]int      `json:"rejected_by_source"`
	ByReason            map[string]int      `json:"by_reason"`
	ByDecision          map[string]int      `json:"by_decision"`
	Duplicates          int                 `json:"duplicates"`
	DuplicateGroups     int                 `json:"duplicate_groups"`
	DuplicateRelations  []duplicateRelation `json:"duplicate_relations,omitempty"`
	Repairs             int                 `json:"repairs"`
	Overlong            int                 `json:"overlong"`
	Unadaptable         int                 `json:"unadaptable"`
	MissingOptional     []string            `json:"missing_optional,omitempty"`
	ReviewApproved      int                 `json:"review_approved"`
	ReviewRejected      int                 `json:"review_rejected"`
	ReviewStale         int                 `json:"review_stale"`
	CanonicalQuarantine int                 `json:"canonical_quarantine"`
	DuplicateQuarantine int                 `json:"duplicate_quarantine"`
	Rejected            int                 `json:"rejected"`
	QuarantineRows      int                 `json:"quarantine_rows"`
	ManifestPayloadHash string              `json:"manifest_payload_hash,omitempty"`
}

type GovernanceReport struct {
	Manifest   GovernanceManifest `json:"manifest"`
	Formal     []Case             `json:"-"`
	Quarantine []Case             `json:"-"`
}

type governanceIssue struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	RawHash string `json:"raw_hash,omitempty"`
	Reason  string `json:"reason"`
}

type governanceRecord struct {
	Case                 Case
	source               SourceSpec
	path                 string
	line                 int
	rawHash, fingerprint string
	reasons              []string
	hard                 bool
	quality              int
	decision             string
	review               *ReviewEntry
	formal               bool
}

type duplicateRelation struct {
	Fingerprint      string `json:"fingerprint"`
	DuplicateRawHash string `json:"duplicate_raw_hash"`
	DuplicateSource  string `json:"duplicate_source"`
	DuplicatePath    string `json:"duplicate_path"`
	DuplicateLine    int    `json:"duplicate_line"`
	RetainedRawHash  string `json:"retained_raw_hash"`
	RetainedSource   string `json:"retained_source"`
	RetainedPath     string `json:"retained_path"`
	RetainedLine     int    `json:"retained_line"`
}

type duplicateObservation = duplicateRelation

// sentryDSNRE intentionally requires the public Sentry DSN shape rather than
// treating arbitrary URLs or identifiers as secrets. The key is the sensitive
// component; the ingest host and project are retained for audit context.
var sentryDSNRE = regexp.MustCompile(`(?i)(https://)[A-Za-z0-9]{16,64}(@o[0-9]+\.ingest\.[a-z0-9-]+\.sentry\.io/[0-9]+)`)
var secretRE = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|(?i)(api[_-]?key|token|secret|password)(\s*[:=]\s*)[^\s,&]+|(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)
var emailRE = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)

// uriUserinfoRE is deliberately limited to HTTP(S) authority userinfo. It
// does not treat colons in ordinary paths, arbitrary URLs, or email addresses
// as credentials.
var uriUserinfoRE = regexp.MustCompile(`(?i)(https?://)[^/\s?#@]+:[^/\s?#@]*@([^/\s?#]+)`)
var placeholderRE = regexp.MustCompile(`(?i)(?:\{\{\s*(?:placeholder|your[_ -]?|todo|example)|\$\{\s*(?:placeholder|your[_ -]?|todo|example)|\{(?:file|path|host|target|username|user|id|value|payload|token|api[_-]?key)\}|<\s*(?:target|host|placeholder)\s*>|YOUR[_ -]?(?:API|TOKEN|KEY)|REPLACE_ME)`)
var allowedCorpusLicenses = map[string]struct{}{
	"repository-curated": {}, "internal": {}, "project-license": {},
	"mit": {}, "apache-2.0": {}, "apache2": {}, "bsd-2-clause": {}, "bsd-3-clause": {},
	"cc0-1.0": {}, "cc-by-4.0": {}, "mpl-2.0": {}, "gpl-2.0-only": {}, "gpl-3.0-only": {},
	"lgpl-2.1": {}, "lgpl-3.0": {}, "unlicense": {},
}

func RunGovernance(ctx context.Context, cfg GovernanceConfig) (GovernanceReport, error) {
	var out GovernanceReport
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if cfg.RuleVersion == "" {
		cfg.RuleVersion = "v1"
	}
	if cfg.PipelineVersion == "" {
		cfg.PipelineVersion = "corpus-governance-v1"
	}
	if err := validateGovernanceLimits(cfg.Limits); err != nil {
		return out, err
	}
	out.Manifest = GovernanceManifest{
		Pipeline:        cfg.PipelineVersion,
		Version:         cfg.RuleVersion,
		ReviewDecisions: []ReviewEntry{},
		InputHashes:     map[string]string{},
		OutputHashes:    map[string]string{},
		Counts: map[string]int{
			"missing_optional":     0,
			"duplicate":            0,
			"formal":               0,
			"quarantine":           0,
			"parse_error":          0,
			"invalid_utf8":         0,
			"overlong":             0,
			"rejected":             0,
			"canonical_quarantine": 0,
			"duplicate_quarantine": 0,
			"quarantine_rows":      0,
		},
		BySource:         map[string]int{},
		RowsBySource:     map[string]int{},
		RejectedBySource: map[string]int{},
		ByReason: map[string]int{
			"missing_optional": 0,
			"parse_error":      0,
			"invalid_utf8":     0,
			"overlong":         0,
			"label_conflict":   0,
		},
		// Keep the hard-reject counter present even when its value is zero. The
		// governed semantic gate treats a missing counter as a malformed manifest,
		// never as an implicit clean result.
		ByDecision: map[string]int{"hard_reject": 0},
		Limits:     governanceLimits(cfg.Limits),
	}
	cfg.Limits = out.Manifest.Limits
	allSources := append([]SourceSpec{}, cfg.Sources...)
	allSources = append(allSources, cfg.Existing...)
	allSources = append(allSources, cfg.Incoming...)
	if len(allSources) == 0 {
		return out, errors.New("governance config requires at least one source")
	}
	if err := validateSourcePaths(allSources); err != nil {
		return out, err
	}
	for i := range allSources {
		if strings.TrimSpace(allSources[i].Name) == "" {
			allSources[i].Name = filepath.Base(allSources[i].Path)
		}
	}
	out.Manifest.SourceSpecs = append([]SourceSpec(nil), allSources...)
	out.Manifest.PolicyHash = governancePolicyHash(cfg, allSources)
	if err := validateOutputPaths(cfg, allSources); err != nil {
		return out, err
	}
	seenRaw := map[string]*governanceRecord{}
	seenFP := map[string]*governanceRecord{}
	var duplicateObservations []duplicateObservation
	var duplicateRecords []governanceRecord
	var issues []governanceIssue
	duplicateGroups := map[string]bool{}
	for _, src := range allSources {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if isRemoteCorpusPath(src.Path) {
			return out, fmt.Errorf("corpus source must be a local file: %s", src.Path)
		}
		name := src.Name
		f, err := os.Open(src.Path)
		if err != nil {
			if src.Optional && errors.Is(err, os.ErrNotExist) {
				out.Manifest.MissingOptional = append(out.Manifest.MissingOptional, src.Path)
				out.Manifest.Counts["missing_optional"]++
				out.Manifest.ByReason["missing_optional"]++
				continue
			}
			return out, fmt.Errorf("open %s: %w", src.Path, err)
		}
		ih, recs, sourceIssues, err := readSource(ctx, f, src, name, &out.Manifest)
		_ = f.Close()
		if err != nil {
			return out, err
		}
		if !src.Optional && len(recs) == 0 {
			return out, fmt.Errorf("required corpus source %q contains no adaptable records", name)
		}
		out.Manifest.InputHashes[src.Path] = ih
		issues = append(issues, sourceIssues...)
		for i := range recs {
			// Take the address of a record owned by the slice, not the range
			// variable. This keeps both indexes attached to the same canonical
			// record even when a later duplicate replaces it.
			r := &recs[i]
			if old := seenRaw[r.rawHash]; old != nil {
				oldCopy := *old
				candidateBetter := better(*r, *old)
				mergeDuplicate(r, old, seenRaw, seenFP)
				if candidateBetter {
					duplicateRecords = append(duplicateRecords, duplicateCopy(&oldCopy, old, "duplicate_exact"))
					duplicateObservations = append(duplicateObservations, observeDuplicate(&oldCopy, old))
				} else {
					duplicateRecords = append(duplicateRecords, duplicateCopy(r, old, "duplicate_exact"))
					duplicateObservations = append(duplicateObservations, observeDuplicate(r, old))
				}
				duplicateGroups[old.fingerprint] = true
				out.Manifest.Duplicates++
				out.Manifest.Counts["duplicate"]++
				out.Manifest.Quarantine++
				out.Manifest.Counts["quarantine"]++
				out.Manifest.BySource[duplicateRecords[len(duplicateRecords)-1].source.Name]++
				continue
			}
			if old := seenFP[r.fingerprint]; old != nil {
				oldCopy := *old
				candidateBetter := better(*r, *old)
				mergeDuplicate(r, old, seenRaw, seenFP)
				if candidateBetter {
					duplicateRecords = append(duplicateRecords, duplicateCopy(&oldCopy, old, "duplicate_semantic"))
					duplicateObservations = append(duplicateObservations, observeDuplicate(&oldCopy, old))
				} else {
					duplicateRecords = append(duplicateRecords, duplicateCopy(r, old, "duplicate_semantic"))
					duplicateObservations = append(duplicateObservations, observeDuplicate(r, old))
				}
				duplicateGroups[r.fingerprint] = true
				out.Manifest.Duplicates++
				out.Manifest.Counts["duplicate"]++
				out.Manifest.Quarantine++
				out.Manifest.Counts["quarantine"]++
				out.Manifest.BySource[duplicateRecords[len(duplicateRecords)-1].source.Name]++
				continue
			}
			seenRaw[r.rawHash] = r
			seenFP[r.fingerprint] = r
		}
	}
	out.Manifest.DuplicateGroups = len(duplicateGroups)
	reviews := map[string]ReviewEntry{}
	reviewEntries := append([]ReviewEntry(nil), cfg.Reviews...)
	if cfg.ReviewPath != "" {
		digest, err := hashRegularFile(cfg.ReviewPath)
		if err != nil {
			return out, fmt.Errorf("hash review input: %w", err)
		}
		out.Manifest.ReviewInputHash = digest
		loaded, err := loadReviews(cfg.ReviewPath)
		if err != nil {
			return out, err
		}
		reviewEntries = append(reviewEntries, loaded...)
	}
	for _, rv := range reviewEntries {
		if strings.TrimSpace(rv.Fingerprint) == "" {
			return out, errors.New("review entry fingerprint is required")
		}
		if strings.TrimSpace(rv.RuleVersion) == "" {
			return out, fmt.Errorf("review entry %s has no rule_version", rv.Fingerprint)
		}
		if strings.TrimSpace(rv.Reviewer) == "" {
			return out, fmt.Errorf("review entry %s has no reviewer", rv.Fingerprint)
		}
		decision, err := normalizeReviewDecision(rv.Decision)
		if err != nil {
			return out, fmt.Errorf("review entry %s: %w", rv.Fingerprint, err)
		}
		rv.Decision = decision
		rv.Fingerprint = strings.TrimSpace(rv.Fingerprint)
		rv.RuleVersion = strings.TrimSpace(rv.RuleVersion)
		rv.Reviewer = strings.TrimSpace(rv.Reviewer)
		rv.Reason = strings.TrimSpace(rv.Reason)
		rv.ReviewedAt = strings.TrimSpace(rv.ReviewedAt)
		if rv.ReviewedAt != "" {
			if _, err := time.Parse(time.RFC3339, rv.ReviewedAt); err != nil {
				return out, fmt.Errorf("review entry %s has invalid reviewed_at: %w", rv.Fingerprint, err)
			}
		}
		if rv.RuleVersion != cfg.RuleVersion {
			return out, fmt.Errorf("review entry %s has rule_version %q, want %q", rv.Fingerprint, rv.RuleVersion, cfg.RuleVersion)
		}
		if old, ok := reviews[rv.Fingerprint]; ok {
			if reviewEntryKey(old) != reviewEntryKey(rv) {
				return out, fmt.Errorf("review entry %s has conflicting decisions or metadata", rv.Fingerprint)
			}
			continue
		}
		reviews[rv.Fingerprint] = rv
		out.Manifest.ReviewDecisions = append(out.Manifest.ReviewDecisions, rv)
	}
	sort.Slice(out.Manifest.ReviewDecisions, func(i, j int) bool {
		return reviewEntryKey(out.Manifest.ReviewDecisions[i]) < reviewEntryKey(out.Manifest.ReviewDecisions[j])
	})
	out.Manifest.ReviewHash = reviewEntriesHash(out.Manifest.ReviewDecisions)
	// A semantic alias can point to the same canonical record more than once.
	// Collapse those pointers before grading, then sort them for reproducible
	// output and review accounting.
	unique := make(map[*governanceRecord]struct{}, len(seenFP))
	for _, r := range seenFP {
		unique[r] = struct{}{}
	}
	records := make([]*governanceRecord, 0, len(unique))
	for r := range unique {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return recordKey(*records[i]) < recordKey(*records[j]) })
	knownFingerprints := make(map[string]bool, len(records))
	for _, r := range records {
		knownFingerprints[r.fingerprint] = true
	}
	var staleReviews []string
	for fingerprint := range reviews {
		if !knownFingerprints[fingerprint] {
			out.Manifest.ReviewStale++
			out.Manifest.ByReason["review_unknown_fingerprint"]++
			staleReviews = append(staleReviews, fingerprint)
		}
	}
	if len(staleReviews) > 0 {
		sort.Strings(staleReviews)
		return out, fmt.Errorf("review entries reference unknown fingerprints: %s", strings.Join(staleReviews, ", "))
	}
	formalRecords := make([]governanceRecord, 0, len(records))
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		r.Case = sanitizeCase(r.Case)
		decision := ""
		reviewed := false
		if rv, ok := reviews[r.fingerprint]; ok {
			decision = rv.Decision
			reviewed = true
			rvCopy := rv
			r.review = &rvCopy
		}
		if decision == "" {
			switch {
			case !r.source.AllowFormal:
				appendReason(&r.reasons, "review_required")
				decision = "ineligible"
			case r.hard:
				decision = "hard_reject"
			case requiresReview(*r):
				appendReason(&r.reasons, "review_required")
				decision = "pending"
			default:
				// Clean, provenance-approved rows do not need an individual
				// review. Only rows routed to isolation require approval.
				decision = "auto"
			}
		}
		if decision != "" {
			out.Manifest.ByDecision[decision]++
		}
		if decision == "approve" {
			out.Manifest.ReviewApproved++
		} else if decision == "reject" {
			out.Manifest.ReviewRejected++
			appendReason(&r.reasons, "review_rejected")
		}
		// Review approval explicitly authorizes reviewable findings such as a
		// repaired row. Sensitive data, structural rejects and provenance failures
		// are hard gates and remain ineligible regardless of review.
		formal := !r.hard && r.source.AllowFormal && (decision == "approve" || decision == "auto")
		r.quality = qualityOf(*r)
		if reviewed && decision == "approve" {
			// Approval authorises reviewable findings, but the provenance and
			// structural hard gates above remain binding.
			formal = !r.hard && r.source.AllowFormal
		}
		if formal {
			r.decision = decision
			r.formal = true
			formalRecords = append(formalRecords, *r)
			out.Formal = append(out.Formal, r.Case)
			out.Manifest.Formal++
			out.Manifest.Counts["formal"]++
		} else {
			r.decision = decision
			out.Quarantine = append(out.Quarantine, r.Case)
			out.Manifest.Quarantine++
			out.Manifest.Counts["quarantine"]++
		}
		for _, reason := range r.reasons {
			out.Manifest.ByReason[reason]++
		}
		out.Manifest.BySource[r.source.Name]++
	}
	out.Manifest.CanonicalQuarantine = len(records) - len(formalRecords)
	out.Manifest.DuplicateQuarantine = len(duplicateRecords)
	out.Manifest.Rejected = len(issues)
	out.Manifest.QuarantineRows = out.Manifest.CanonicalQuarantine + out.Manifest.DuplicateQuarantine + out.Manifest.Rejected
	out.Manifest.Counts["rejected"] = out.Manifest.Rejected
	out.Manifest.Counts["canonical_quarantine"] = out.Manifest.CanonicalQuarantine
	out.Manifest.Counts["duplicate_quarantine"] = out.Manifest.DuplicateQuarantine
	out.Manifest.Counts["quarantine_rows"] = out.Manifest.QuarantineRows
	for _, r := range duplicateRecords {
		for _, reason := range r.reasons {
			out.Manifest.ByReason[reason]++
		}
	}
	for i := range duplicateObservations {
		if retained := seenFP[duplicateObservations[i].Fingerprint]; retained != nil {
			duplicateObservations[i].RetainedRawHash = retained.rawHash
			duplicateObservations[i].RetainedSource = retained.source.Name
			duplicateObservations[i].RetainedPath = retained.path
			duplicateObservations[i].RetainedLine = retained.line
		}
	}
	sort.Slice(out.Formal, func(i, j int) bool { return caseKey(out.Formal[i]) < caseKey(out.Formal[j]) })
	sort.Slice(out.Quarantine, func(i, j int) bool { return caseKey(out.Quarantine[i]) < caseKey(out.Quarantine[j]) })
	sort.Slice(duplicateObservations, func(i, j int) bool {
		if duplicateObservations[i].Fingerprint != duplicateObservations[j].Fingerprint {
			return duplicateObservations[i].Fingerprint < duplicateObservations[j].Fingerprint
		}
		if duplicateObservations[i].DuplicatePath != duplicateObservations[j].DuplicatePath {
			return duplicateObservations[i].DuplicatePath < duplicateObservations[j].DuplicatePath
		}
		return duplicateObservations[i].DuplicateLine < duplicateObservations[j].DuplicateLine
	})
	out.Manifest.DuplicateRelations = duplicateObservations
	sort.Strings(out.Manifest.MissingOptional)
	quarantineRecords := make([]governanceRecord, 0, out.Manifest.Quarantine)
	formalKeys := make(map[string]bool, len(out.Formal))
	for _, tc := range out.Formal {
		formalKeys[caseKey(tc)] = true
	}
	for _, r := range records {
		if !formalKeys[caseKey(r.Case)] {
			quarantineRecords = append(quarantineRecords, *r)
		}
	}
	quarantineRecords = append(quarantineRecords, duplicateRecords...)
	sort.Slice(quarantineRecords, func(i, j int) bool { return recordKey(quarantineRecords[i]) < recordKey(quarantineRecords[j]) })
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Line < issues[j].Line
	})
	sort.Slice(formalRecords, func(i, j int) bool { return recordKey(formalRecords[i]) < recordKey(formalRecords[j]) })
	if err := writeOutputs(cfg, formalRecords, quarantineRecords, issues, &out.Manifest); err != nil {
		return out, err
	}
	return out, nil
}

// validateSourcePaths rejects a source file being declared more than once in
// any of the Sources/Existing/Incoming lists. Re-reading the same file under
// different provenance would make row counts and source hashes ambiguous even
// though the later record de-duplication pass collapses identical rows.
func validateSourcePaths(sources []SourceSpec) error {
	seen := make([]string, 0, len(sources))
	for _, source := range sources {
		if strings.TrimSpace(source.Path) == "" {
			return errors.New("governance config source path is empty")
		}
		for _, previous := range seen {
			if sameCorpusPath(previous, source.Path) {
				return fmt.Errorf("governance config contains duplicate source path %q", source.Path)
			}
		}
		seen = append(seen, source.Path)
	}
	return nil
}

func validateOutputPaths(cfg GovernanceConfig, src []SourceSpec) error {
	if strings.TrimSpace(cfg.ReviewPath) != "" {
		for _, source := range src {
			if strings.TrimSpace(source.Path) == "" {
				continue
			}
			if sameCorpusPath(cfg.ReviewPath, source.Path) {
				return fmt.Errorf("review path overlaps input: %s", cfg.ReviewPath)
			}
		}
	}
	outs := []string{cfg.FormalPath, cfg.QuarantinePath, cfg.ManifestPath}
	seen := make([]string, 0, len(outs))
	for _, p := range outs {
		if p == "" {
			return errors.New("all output paths are required")
		}
		if isRemoteCorpusPath(p) {
			return fmt.Errorf("output path must be local: %s", p)
		}
		for _, previous := range seen {
			if sameCorpusPath(previous, p) {
				return fmt.Errorf("duplicate output path %s", p)
			}
		}
		seen = append(seen, p)
		for _, s := range src {
			if sameCorpusPath(p, s.Path) {
				return fmt.Errorf("output path overlaps input: %s", p)
			}
		}
		if cfg.ReviewPath != "" {
			if sameCorpusPath(p, cfg.ReviewPath) {
				return fmt.Errorf("output path overlaps review input: %s", p)
			}
		}
	}
	return nil
}

func sameCorpusPath(a, b string) bool {
	canonicalA := canonicalCorpusPath(a)
	canonicalB := canonicalCorpusPath(b)
	if canonicalA == canonicalB || strings.EqualFold(canonicalA, canonicalB) {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

func canonicalCorpusPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Clean(filepath.Join(resolved, filepath.Base(abs)))
	}
	return abs
}

func readSource(ctx context.Context, f *os.File, src SourceSpec, name string, m *GovernanceManifest) (string, []governanceRecord, []governanceIssue, error) {
	info, err := f.Stat()
	if err != nil {
		return "", nil, nil, fmt.Errorf("stat %s: %w", src.Path, err)
	}
	if !info.Mode().IsRegular() {
		return "", nil, nil, fmt.Errorf("corpus source must be a regular file: %s", src.Path)
	}
	if info.Size() > m.Limits.MaxInputBytes {
		return "", nil, nil, fmt.Errorf("corpus source %s exceeds max_input_bytes: %d > %d", src.Path, info.Size(), m.Limits.MaxInputBytes)
	}
	h := sha256.New()
	compressed := &countingReader{r: io.TeeReader(f, h)}
	var rd io.Reader = compressed
	isGzip := strings.HasSuffix(strings.ToLower(src.Path), ".gz")
	if isGzip {
		gz, err := gzip.NewReader(compressed)
		if err != nil {
			return "", nil, nil, fmt.Errorf("open gzip %s: %w", src.Path, err)
		}
		defer gz.Close()
		rd = gz
	}
	budget := &governanceBudgetReader{
		r:                 rd,
		compressed:        compressed,
		maxDecompressed:   m.Limits.MaxDecompressedBytes,
		maxExpansionRatio: m.Limits.MaxExpansionRatio,
		checkExpansion:    isGzip,
	}
	br := bufio.NewReaderSize(budget, 64*1024)
	max := corpusMaxLineBytes()
	var recs []governanceRecord
	var issues []governanceIssue
	lineNo := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", nil, nil, err
		}
		line, over, e := readBoundedJSONLLine(br, max)
		if len(line) > 0 || e == nil {
			lineNo++
		}
		line = bytesTrimSpace(line)
		if len(line) > 0 {
			if m.Total >= m.Limits.MaxRecords {
				return "", nil, nil, fmt.Errorf("corpus governance exceeds max_records: %d", m.Limits.MaxRecords)
			}
			m.Total++
			m.RowsBySource[name]++
			if over || len(line) > max {
				m.Overlong++
				m.Counts["overlong"]++
				m.ByReason["overlong"]++
				m.RejectedBySource[name]++
				issues = append(issues, governanceIssue{Source: name, Path: src.Path, Line: lineNo, RawHash: hashBytes(line), Reason: "overlong"})
			} else {
				r, err := parseRecord(line, lineNo, src, name)
				if err != nil {
					reason := "parse_error"
					if err.Error() == "invalid_utf8" {
						reason = "invalid_utf8"
					}
					m.Counts[reason]++
					m.ByReason[reason]++
					m.RejectedBySource[name]++
					issues = append(issues, governanceIssue{Source: name, Path: src.Path, Line: lineNo, RawHash: hashBytes(line), Reason: reason})
					var shape struct {
						Method string `json:"method"`
						URL    string `json:"url"`
						Data   string `json:"data"`
					}
					if json.Unmarshal(line, &shape) == nil && (shape.Method != "" || shape.URL != "" || shape.Data != "") {
						m.Unadaptable++
					}
				} else {
					if strings.Contains(r.Case.Rationale, "repaired:") {
						m.Repairs++
					}
					recs = append(recs, r)
				}
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", nil, nil, fmt.Errorf("read %s: %w", src.Path, e)
		}
	}
	if err := budget.Err(); err != nil {
		return "", nil, nil, fmt.Errorf("read %s: %w", src.Path, err)
	}
	if isGzip && compressed.n > 0 && float64(budget.decompressed) > float64(compressed.n)*m.Limits.MaxExpansionRatio {
		return "", nil, nil, fmt.Errorf("read %s: gzip expansion ratio %.2f exceeds max_expansion_ratio %.2f", src.Path, float64(budget.decompressed)/float64(compressed.n), m.Limits.MaxExpansionRatio)
	}
	// gzip readers may stop at the end of the first stream. Hash any trailing
	// bytes as part of the immutable source file even though they are not corpus
	// records; changing them must still invalidate the manifest.
	if _, err := io.Copy(h, f); err != nil {
		return "", nil, nil, fmt.Errorf("finish hashing %s: %w", src.Path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), recs, issues, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

type governanceBudgetReader struct {
	r                 io.Reader
	compressed        *countingReader
	decompressed      int64
	maxDecompressed   int64
	maxExpansionRatio float64
	checkExpansion    bool
	err               error
}

func (r *governanceBudgetReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	r.decompressed += int64(n)
	if r.decompressed > r.maxDecompressed {
		r.err = fmt.Errorf("decompressed input exceeds max_decompressed_bytes: %d > %d", r.decompressed, r.maxDecompressed)
		return n, r.err
	}
	// Allow a small startup window because gzip readers buffer compressed data.
	// Once both sides have meaningful counts, enforce the declared ratio while
	// streaming so a highly compressed bomb stops well before the byte ceiling.
	if r.checkExpansion && r.compressed.n > 0 && r.decompressed >= 64*1024 &&
		float64(r.decompressed) > float64(r.compressed.n)*r.maxExpansionRatio {
		r.err = fmt.Errorf("gzip expansion ratio exceeds max_expansion_ratio %.2f", r.maxExpansionRatio)
		return n, r.err
	}
	return n, err
}

func (r *governanceBudgetReader) Err() error { return r.err }

func bytesTrimSpace(b []byte) []byte { return bytes.TrimSpace(b) }

func parseRecord(line []byte, lineNo int, src SourceSpec, name string) (governanceRecord, error) {
	if !utf8.Valid(line) {
		return governanceRecord{source: src}, errors.New("invalid_utf8")
	}
	r := governanceRecord{source: src, path: src.Path, line: lineNo}
	r.source.Name = name
	r.rawHash = hashBytes(line)
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(line, &shape); err == nil && shape != nil {
		duplicateJSONKeys, err := hasDuplicateJSONKeys(line)
		if err != nil {
			return r, err
		}
		switch {
		case hasJSONKey(shape, "target", "Target", "body", "Body", "header", "Header", "content_type", "ContentType", "source_family", "SourceFamily", "rationale", "Rationale"):
			var tc Case
			if err := json.Unmarshal(line, &tc); err != nil {
				return r, err
			}
			if err := ValidateCase(tc); err != nil {
				return r, fmt.Errorf("invalid normalized case: %w", err)
			}
			r.Case = tc

		case hasJSONKey(shape, "payload"):
			var p struct {
				Payload  string `json:"payload"`
				Label    string `json:"label"`
				Category string `json:"category"`
				Name     string `json:"name"`
			}
			if err := json.Unmarshal(line, &p); err != nil || p.Payload == "" {
				return r, errors.New("payload record requires a non-empty payload")
			}
			truth := strings.ToLower(strings.TrimSpace(src.DefaultTruth))
			if truth == "" {
				truth = strings.ToLower(strings.TrimSpace(p.Label))
			}
			if truth != "attack" && truth != "benign" {
				return r, fmt.Errorf("unsupported ground truth %q", truth)
			}
			category := p.Category
			if truth == "attack" && category == "" {
				category = NormalizeCategory(p.Label)
			}
			r.Case = Case{Name: firstNonEmpty(p.Name, fmt.Sprintf("%s#%d", name, lineNo)), SourceFamily: name, Label: truth, Category: category, Method: "POST", Target: "/", Body: p.Payload}

		case hasJSONKey(shape, "url", "data", "headers", "expected_detection"):
			var raw RawHTTPCase
			if err := json.Unmarshal(line, &raw); err != nil {
				return r, err
			}
			c, err := AdaptRawHTTPCase(raw, fmt.Sprintf("%s#%d", name, lineNo), src.DefaultTruth)
			if err != nil {
				return r, err
			}
			if malformed := malformedHeaderLines(raw.Headers); malformed > 0 {
				c.Rationale = appendRationale(c.Rationale, "repaired: malformed header line omitted")
				appendReason(&r.reasons, "header_parse_loss")
				r.hard = true
			}
			if duplicate := duplicateHeaderLines(raw.Headers); duplicate > 0 {
				c.Rationale = appendRationale(c.Rationale, "isolated: duplicate header values joined")
				appendReason(&r.reasons, "header_parse_loss")
				appendReason(&r.reasons, "duplicate_header")
				r.hard = true
			}
			r.Case = c

		default:
			return r, errors.New("unrecognised record")
		}
		if duplicateJSONKeys {
			appendReason(&r.reasons, "duplicate_json_key")
			r.hard = true
		}
	} else {
		var payload string
		if json.Unmarshal(line, &payload) != nil || payload == "" {
			return r, errors.New("unrecognised record")
		}
		truth := strings.ToLower(strings.TrimSpace(src.DefaultTruth))
		if truth != "attack" && truth != "benign" {
			return r, fmt.Errorf("unsupported ground truth %q", truth)
		}
		category := ""
		if truth == "attack" {
			category = CategoryGeneric
		}
		r.Case = Case{Name: fmt.Sprintf("%s#%d", name, lineNo), SourceFamily: name, Label: truth, Category: category, Method: "POST", Target: "/", Body: payload}
	}
	if err := ValidateCase(r.Case); err != nil {
		return r, err
	}
	r.fingerprint = semanticFingerprint(r.Case)
	screenReasons, screenHard := screen(r.Case, src)
	for _, reason := range screenReasons {
		appendReason(&r.reasons, reason)
	}
	r.hard = r.hard || screenHard
	r.quality = qualityOf(r)
	return r, nil
}

func hasJSONKey(object map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		if _, ok := object[key]; ok {
			return true
		}
	}
	return false
}

// hasDuplicateJSONKeys detects duplicate object members before encoding/json
// silently keeps only the last value. Keys are compared case-insensitively
// because the supported corpus structs also match JSON field names that way.
func hasDuplicateJSONKeys(data []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := scanJSONValue(decoder)
	if err != nil {
		return false, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return true, nil
		}
		return false, err
	}
	return duplicate, nil
}

func scanJSONValue(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		duplicate := false
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, errors.New("json object key is not a string")
			}
			keyForComparison := strings.ToLower(key)
			if _, exists := seen[keyForComparison]; exists {
				duplicate = true
			}
			seen[keyForComparison] = struct{}{}
			childDuplicate, err := scanJSONValue(decoder)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	case '[':
		duplicate := false
		for decoder.More() {
			childDuplicate, err := scanJSONValue(decoder)
			if err != nil {
				return false, err
			}
			duplicate = duplicate || childDuplicate
		}
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		return duplicate, nil
	default:
		return false, nil
	}
}

func malformedHeaderLines(block string) int {
	malformed := 0
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || !validHeaderFieldName(name) {
			malformed++
		}
	}
	return malformed
}

func duplicateHeaderLines(block string) int {
	seen := make(map[string]struct{})
	duplicates := 0
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || !validHeaderFieldName(name) {
			continue
		}
		canonical := strings.ToLower(name)
		if _, exists := seen[canonical]; exists {
			duplicates++
			continue
		}
		seen[canonical] = struct{}{}
	}
	return duplicates
}

func appendRationale(existing, addition string) string {
	if strings.TrimSpace(existing) == "" {
		return addition
	}
	return existing + "; " + addition
}

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

const (
	defaultGovernanceMaxRecords           = 5_000_000
	defaultGovernanceMaxInputBytes        = int64(8 << 30)
	defaultGovernanceMaxDecompressedBytes = int64(4 << 30)
	defaultGovernanceMaxExpansionRatio    = 500.0
)

func governanceLimits(l GovernanceLimits) GovernanceLimits {
	if l.MaxRecords <= 0 {
		l.MaxRecords = defaultGovernanceMaxRecords
	}
	if l.MaxInputBytes <= 0 {
		l.MaxInputBytes = defaultGovernanceMaxInputBytes
	}
	if l.MaxDecompressedBytes <= 0 {
		l.MaxDecompressedBytes = defaultGovernanceMaxDecompressedBytes
	}
	if l.MaxExpansionRatio <= 0 {
		l.MaxExpansionRatio = defaultGovernanceMaxExpansionRatio
	}
	return l
}

func validateGovernanceLimits(l GovernanceLimits) error {
	if l.MaxRecords < 0 || l.MaxInputBytes < 0 || l.MaxDecompressedBytes < 0 || l.MaxExpansionRatio < 0 || math.IsNaN(l.MaxExpansionRatio) || math.IsInf(l.MaxExpansionRatio, 0) {
		return errors.New("governance limits must be finite non-negative values; zero selects the default")
	}
	return nil
}

func hashRegularFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func governancePolicyHash(cfg GovernanceConfig, sources []SourceSpec) string {
	payload := struct {
		PipelineVersion string           `json:"pipeline_version"`
		RuleVersion     string           `json:"rule_version"`
		Sources         []SourceSpec     `json:"sources"`
		Limits          GovernanceLimits `json:"limits"`
	}{
		PipelineVersion: cfg.PipelineVersion,
		RuleVersion:     cfg.RuleVersion,
		Sources:         sources,
		Limits:          governanceLimits(cfg.Limits),
	}
	encoded, _ := json.Marshal(payload)
	return hashBytes(encoded)
}

func reviewEntriesHash(entries []ReviewEntry) string {
	encoded, _ := json.Marshal(entries)
	return hashBytes(encoded)
}

func reviewEntryKey(entry ReviewEntry) string {
	return strings.Join([]string{
		entry.Fingerprint,
		entry.RuleVersion,
		entry.Decision,
		entry.Reviewer,
		entry.Reason,
		entry.ReviewedAt,
	}, "\x00")
}

func semanticFingerprint(c Case) string {
	var b strings.Builder
	writeFingerprintPart(&b, strings.ToUpper(strings.TrimSpace(c.Method)))
	writeFingerprintPart(&b, normalizeTargetForFingerprint(c.Target))
	writeFingerprintPart(&b, strings.TrimSpace(c.ContentType))
	// Bodies are protocol data, not prose. Whitespace can change JSON string
	// values, multipart boundaries, signatures, SQL tokens and parser behavior,
	// so the dedup key must preserve it byte-for-byte.
	writeFingerprintPart(&b, c.Body)
	type headerPart struct {
		name  string
		value string
	}
	headers := make([]headerPart, 0, len(c.Header))
	for n, value := range c.Header {
		key := strings.ToLower(strings.TrimSpace(n))
		headers = append(headers, headerPart{name: key, value: value})
	}
	// Sorting normalized name/value pairs makes case-insensitive header names
	// stable without collapsing two differently-cased keys that coexist in a
	// JSON object. Authorization and Cookie are intentionally retained: both are
	// real WAF attack surfaces and cannot be treated as volatile metadata.
	sort.Slice(headers, func(i, j int) bool {
		if headers[i].name != headers[j].name {
			return headers[i].name < headers[j].name
		}
		return headers[i].value < headers[j].value
	})
	for _, header := range headers {
		writeFingerprintPart(&b, header.name)
		writeFingerprintPart(&b, header.value)
	}
	return hashBytes([]byte(b.String()))
}

func writeFingerprintPart(b *strings.Builder, value string) {
	fmt.Fprintf(b, "%d:", len(value))
	b.WriteString(value)
}
func qualityOf(r governanceRecord) int {
	q := 0
	if r.source.AllowFormal && sourceProvenanceOK(r.source) {
		q += 4
	}
	if r.Case.Rationale == "" {
		q += 2
	}
	if !r.hard {
		q++
	}
	q -= len(r.reasons)
	return q
}
func better(a, b governanceRecord) bool { return a.quality > b.quality }

func normalizeTargetForFingerprint(target string) string {
	trimmed := strings.TrimSpace(target)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String()
}

func sourceProvenanceOK(src SourceSpec) bool {
	license := strings.ToLower(strings.TrimSpace(src.License))
	if _, ok := allowedCorpusLicenses[license]; !ok {
		return false
	}
	access := strings.ToLower(strings.TrimSpace(src.Access))
	switch access {
	case "local-file", "public-direct", "public-direct-download", "public-repository":
		return true
	default:
		return false
	}
}

func isRemoteCorpusPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	return strings.Contains(trimmed, "://") || strings.HasPrefix(strings.ToLower(trimmed), "file:")
}

func observeDuplicate(duplicate, retained *governanceRecord) duplicateObservation {
	return duplicateObservation{
		Fingerprint:      retained.fingerprint,
		DuplicateRawHash: duplicate.rawHash,
		DuplicateSource:  duplicate.source.Name,
		DuplicatePath:    duplicate.path,
		DuplicateLine:    duplicate.line,
		RetainedRawHash:  retained.rawHash,
		RetainedSource:   retained.source.Name,
		RetainedPath:     retained.path,
		RetainedLine:     retained.line,
	}
}

func duplicateCopy(duplicate, retained *governanceRecord, reason string) governanceRecord {
	copy := *duplicate
	copy.Case = sanitizeCase(copy.Case)
	copy.decision = "duplicate"
	copy.review = nil
	copy.formal = false
	appendReason(&copy.reasons, reason)
	if duplicate.Case.Label != retained.Case.Label || duplicate.Case.Category != retained.Case.Category {
		appendReason(&copy.reasons, "label_conflict")
		copy.hard = true
	}
	return copy
}

func mergeDuplicate(candidate, retained *governanceRecord, seenRaw, seenFP map[string]*governanceRecord) {
	labelConflict := candidate.Case.Label != retained.Case.Label || candidate.Case.Category != retained.Case.Category
	groupLabelConflict := labelConflict || hasReason(retained.reasons, "label_conflict")
	if better(*candidate, *retained) {
		oldRawHash := retained.rawHash
		*retained = *candidate
		seenRaw[oldRawHash] = retained
		seenRaw[candidate.rawHash] = retained
		seenFP[retained.fingerprint] = retained
	} else {
		seenRaw[candidate.rawHash] = retained
		seenFP[candidate.fingerprint] = retained
	}
	// A content group that ever carried conflicting labels is permanently
	// ineligible. A later, higher-quality duplicate may replace the canonical
	// row, but it must not erase the conflict accumulated by the group.
	if groupLabelConflict {
		appendReason(&retained.reasons, "label_conflict")
		retained.hard = true
		retained.quality = qualityOf(*retained)
	}
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func normalizeReviewDecision(decision string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "approve", "approved":
		return "approve", nil
	case "reject", "rejected":
		return "reject", nil
	default:
		return "", fmt.Errorf("unsupported decision %q", decision)
	}
}

func recordKey(r governanceRecord) string {
	return r.fingerprint + "|" + r.path + "|" + fmt.Sprintf("%012d", r.line) + "|" + r.rawHash
}

func caseKey(c Case) string {
	return semanticFingerprint(c) + "|" + strings.ToLower(strings.TrimSpace(c.Name))
}

func appendReason(reasons *[]string, reason string) {
	for _, existing := range *reasons {
		if existing == reason {
			return
		}
	}
	*reasons = append(*reasons, reason)
	sort.Strings(*reasons)
}

func requiresReview(r governanceRecord) bool {
	for _, reason := range r.reasons {
		switch reason {
		case "placeholder", "repaired", "label_fidelity_mismatch", "no_fidelity_evidence", "secret_detected", "pii_email_detected", "label_conflict":
			return true
		}
	}
	return false
}

func loadReviews(path string) ([]ReviewEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ReviewEntry
	s := bufio.NewScanner(f)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		duplicate, err := hasDuplicateJSONKeys([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("review file line %d: %w", lineNo, err)
		}
		if duplicate {
			return nil, fmt.Errorf("review file line %d contains duplicate JSON key", lineNo)
		}
		var r ReviewEntry
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("review file line %d: %w", lineNo, err)
		}
		out = append(out, r)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func screen(c Case, src SourceSpec) ([]string, bool) {
	var rs []string
	hard := false
	if !src.AllowFormal {
		appendReason(&rs, "source_not_allowed_formal")
	}
	if !utf8Valid(c) {
		appendReason(&rs, "invalid_utf8")
		hard = true
	}
	if !validRequestShape(c) {
		appendReason(&rs, "invalid_request_shape")
		hard = true
	}
	auditText := caseAuditText(c)
	if placeholderRE.MatchString(auditText) {
		appendReason(&rs, "placeholder")
	}
	if strings.Contains(c.Rationale, "repaired:") {
		appendReason(&rs, "repaired")
	}
	if c.Label == "attack" {
		f := FidelityOf(c)
		if c.Category != "" && !f.InClass {
			appendReason(&rs, "label_fidelity_mismatch")
		}
		if f.NoEvidence {
			appendReason(&rs, "no_fidelity_evidence")
		}
	}
	if sentryDSNRE.MatchString(auditText) || secretRE.MatchString(auditText) || uriUserinfoRE.MatchString(auditText) {
		appendReason(&rs, "secret_detected")
		hard = true
	}
	for name, value := range c.Header {
		if isSecretHeader(name) || (isCookieHeader(name) && sensitiveCookieHeader(value)) {
			appendReason(&rs, "secret_detected")
			hard = true
		}
	}
	if emailRE.MatchString(auditText) {
		appendReason(&rs, "pii_email_detected")
		hard = true
	}
	if !sourceProvenanceOK(src) {
		appendReason(&rs, "source_access_gate")
		hard = true
	}
	return rs, hard
}

func validRequestShape(c Case) bool {
	if _, err := http.NewRequest(c.Method, c.Target, nil); err != nil {
		return false
	}
	if !validHeaderFieldValue(c.ContentType) {
		return false
	}
	seenHeaders := make(map[string]struct{}, len(c.Header))
	for name, value := range c.Header {
		if !validHeaderFieldName(name) || !validHeaderFieldValue(value) {
			return false
		}
		canonicalName := strings.ToLower(strings.TrimSpace(name))
		if _, exists := seenHeaders[canonicalName]; exists {
			return false
		}
		seenHeaders[canonicalName] = struct{}{}
		if canonicalName == "content-type" && strings.TrimSpace(c.ContentType) != "" {
			return false
		}
	}
	return true
}

func validHeaderFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func caseAuditText(c Case) string {
	// Audit the original field values rather than JSON-encoding the case. The
	// encoder escapes HTML-significant bytes (for example <target> becomes
	// \u003ctarget\u003e), which would let placeholder/secret patterns evade
	// screening. Length framing keeps field boundaries deterministic while
	// preserving every byte of the source value.
	var b strings.Builder
	for _, value := range []string{
		c.Name,
		c.SourceFamily,
		c.Label,
		c.Category,
		c.Method,
		c.Target,
		c.ContentType,
		c.Body,
		c.Rationale,
	} {
		writeFingerprintPart(&b, value)
	}
	keys := make([]string, 0, len(c.Header))
	for key := range c.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeFingerprintPart(&b, key)
		writeFingerprintPart(&b, c.Header[key])
	}
	return b.String()
}

func utf8Valid(c Case) bool {
	values := []string{c.Name, c.SourceFamily, c.Label, c.Category, c.Method, c.Target, c.ContentType, c.Body, c.Rationale}
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	for key, value := range c.Header {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

func sanitizeCase(c Case) Case {
	c.Name = sanitizeCorpusText(c.Name)
	c.SourceFamily = sanitizeCorpusText(c.SourceFamily)
	c.Label = sanitizeCorpusText(c.Label)
	c.Category = sanitizeCorpusText(c.Category)
	c.Method = sanitizeCorpusText(c.Method)
	c.ContentType = sanitizeCorpusText(c.ContentType)
	c.Rationale = sanitizeCorpusText(c.Rationale)
	headers := make(map[string]string, len(c.Header))
	for k, value := range c.Header {
		if isSecretHeader(k) || !validHeaderFieldName(k) {
			continue
		} else if isCookieHeader(k) {
			headers[k] = sanitizeCookieHeader(value)
		} else {
			headers[k] = sanitizeCorpusText(value)
		}
	}
	if len(headers) == 0 {
		c.Header = nil
	} else {
		c.Header = headers
	}
	c.Target = sanitizeCorpusText(c.Target)
	c.Body = sanitizeCorpusText(c.Body)
	return c
}

func sanitizeCorpusText(value string) string {
	value = sentryDSNRE.ReplaceAllString(value, "$1[REDACTED]$2")
	value = uriUserinfoRE.ReplaceAllString(value, "$1[REDACTED]@$2")
	value = secretRE.ReplaceAllString(value, "$1[REDACTED]")
	return emailRE.ReplaceAllString(value, "[REDACTED_EMAIL]")
}
func isSecretHeader(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	return k == "authorization" || k == "proxy-authorization" || k == "x-api-key" || k == "x-auth-token" || k == "api-key" || k == "x-xsrf-token" || k == "x-sf-csrf-token" || k == "x-csrf-token" || k == "xsrf-token" || k == "csrf-token"
}

func isCookieHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "cookie", "set-cookie":
		return true
	default:
		return false
	}
}

func sensitiveCookieHeader(value string) bool {
	for _, part := range strings.Split(value, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && sensitiveCookieName(name) {
			return true
		}
	}
	return false
}

func sanitizeCookieHeader(value string) string {
	parts := strings.Split(value, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		name, _, ok := strings.Cut(part, "=")
		if ok && sensitiveCookieName(name) {
			parts[i] = strings.TrimSpace(name) + "=[REDACTED]"
		} else {
			parts[i] = sanitizeCorpusText(part)
		}
	}
	return strings.Join(parts, "; ")
}

func sensitiveCookieName(name string) bool {
	var key strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			key.WriteRune(r)
		}
	}
	normalized := key.String()
	switch normalized {
	case "sid", "auth", "jwt", "csrf", "xsrf", "rememberme", "remembertoken":
		return true
	}
	return strings.Contains(normalized, "session") ||
		strings.HasSuffix(normalized, "token") ||
		strings.HasSuffix(normalized, "sessid")
}

type quarantineEntry struct {
	Case
	Kind         string   `json:"kind,omitempty"`
	Source       string   `json:"source"`
	Path         string   `json:"path"`
	Line         int      `json:"line"`
	RawHash      string   `json:"raw_hash"`
	Fingerprint  string   `json:"fingerprint"`
	Reasons      []string `json:"reasons"`
	Decision     string   `json:"decision,omitempty"`
	RuleVersion  string   `json:"review_rule_version,omitempty"`
	Reviewer     string   `json:"reviewer,omitempty"`
	ReviewReason string   `json:"review_reason,omitempty"`
	ReviewedAt   string   `json:"reviewed_at,omitempty"`
}

type formalEntry struct {
	Case
	Source       string `json:"governance_source"`
	Path         string `json:"governance_path"`
	Line         int    `json:"governance_line"`
	RawHash      string `json:"raw_hash"`
	Fingerprint  string `json:"fingerprint"`
	Decision     string `json:"decision"`
	RuleVersion  string `json:"review_rule_version,omitempty"`
	Reviewer     string `json:"reviewer,omitempty"`
	ReviewReason string `json:"review_reason,omitempty"`
	ReviewedAt   string `json:"reviewed_at,omitempty"`
}

func writeOutputs(cfg GovernanceConfig, formal []governanceRecord, quarantine []governanceRecord, issues []governanceIssue, m *GovernanceManifest) error {
	formalBytes := formalJSONL(formal)
	quarantineBytes := quarantineJSONL(quarantine, issues)
	for _, output := range []struct {
		path string
		data []byte
		key  string
	}{
		{path: cfg.FormalPath, data: formalBytes, key: "formal"},
		{path: cfg.QuarantinePath, data: quarantineBytes, key: "quarantine"},
	} {
		if err := atomicWrite(output.path, output.data); err != nil {
			return err
		}
		m.OutputHashes[output.key] = hashBytes(output.data)
	}
	m.ManifestPayloadHash = ""
	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	m.ManifestPayloadHash = hashBytes(payload)
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(cfg.ManifestPath, manifestBytes); err != nil {
		return err
	}
	return nil
}

func quarantineJSONL(rs []governanceRecord, issues []governanceIssue) []byte {
	var b strings.Builder
	for _, r := range rs {
		entry := quarantineEntry{Case: r.Case, Source: r.source.Name, Path: r.path, Line: r.line, RawHash: r.rawHash, Fingerprint: r.fingerprint, Reasons: r.reasons, Decision: r.decision}
		applyReviewMetadata(r.review, &entry.RuleVersion, &entry.Reviewer, &entry.ReviewReason, &entry.ReviewedAt)
		x, _ := json.Marshal(entry)
		b.Write(x)
		b.WriteByte('\n')
	}
	for _, issue := range issues {
		x, _ := json.Marshal(quarantineEntry{Kind: "rejected_record", Source: issue.Source, Path: issue.Path, Line: issue.Line, RawHash: issue.RawHash, Reasons: []string{issue.Reason}})
		b.Write(x)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func formalJSONL(rs []governanceRecord) []byte {
	var b strings.Builder
	for _, r := range rs {
		entry := formalEntry{Case: r.Case, Source: r.source.Name, Path: r.path, Line: r.line, RawHash: r.rawHash, Fingerprint: r.fingerprint, Decision: r.decision}
		applyReviewMetadata(r.review, &entry.RuleVersion, &entry.Reviewer, &entry.ReviewReason, &entry.ReviewedAt)
		x, _ := json.Marshal(entry)
		b.Write(x)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func applyReviewMetadata(review *ReviewEntry, ruleVersion, reviewer, reason, reviewedAt *string) {
	if review == nil {
		return
	}
	*ruleVersion = review.RuleVersion
	*reviewer = review.Reviewer
	*reason = review.Reason
	*reviewedAt = review.ReviewedAt
}
func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".governance-")
	if err != nil {
		return err
	}
	nerr := error(nil)
	if _, err = f.Write(data); err != nil {
		nerr = err
	}
	if e := f.Close(); nerr == nil {
		nerr = e
	}
	if nerr != nil {
		os.Remove(f.Name())
		return nerr
	}
	return os.Rename(f.Name(), path)
}
