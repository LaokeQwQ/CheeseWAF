package security

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultEvaluationMaxRecords is a finite safety cap for independent
// evaluation inputs. A caller that needs a larger set must opt in explicitly;
// an accidental unbounded reader is never allowed to consume memory forever.
const DefaultEvaluationMaxRecords = 100_000

// DefaultEvaluationJSONLMaxBytes bounds the decompressed input accepted by
// the JSONL loader. A record cap alone is not a memory bound because every
// record may contain a large request body; this limit also protects callers
// reading gzip or other expanding streams.
const DefaultEvaluationJSONLMaxBytes int64 = 256 << 20

// MaxEvaluationJSONLBytes is an absolute ceiling for callers that override
// the default JSONL budget. The slice-backed split command still needs to hold
// validated records and the resulting artifact, so allowing an unbounded
// caller-supplied value would turn a configuration knob into an OOM vector.
const MaxEvaluationJSONLBytes int64 = 512 << 20

// MaxEvaluationRecords is an absolute ceiling shared by JSONL and artifact
// loaders. It is intentionally higher than the default, but finite even when
// a caller supplies an explicit max-records value.
const MaxEvaluationRecords = 1_000_000

// Artifact limits are applied before decoding an evaluation split. The byte
// and token budgets are deliberately finite even when a caller opts into a
// larger record count; this keeps malformed or adversarial JSON from forcing
// an unbounded allocation or recursion depth.
const (
	DefaultEvaluationArtifactMaxBytes  = 64 * 1024 * 1024
	DefaultEvaluationArtifactMaxDepth  = 128
	DefaultEvaluationArtifactMaxTokens = 8_000_000
)

// EvaluationGovernanceBinding records the immutable identity of the
// governance run that produced a split input.  The manifest path itself is
// intentionally not persisted because it is a machine-local detail and may
// contain sensitive directory names; consumers provide the manifest again at
// replay time and verify these hashes instead.
type EvaluationGovernanceBinding struct {
	ManifestSHA256      string `json:"manifest_sha256"`
	ManifestPayloadHash string `json:"manifest_payload_hash"`
	FormalSHA256        string `json:"formal_sha256"`
	InputSHA256         string `json:"input_sha256"`
	FormalRecords       int    `json:"formal_records"`
	Pipeline            string `json:"pipeline"`
	Version             string `json:"version"`
	PolicyHash          string `json:"policy_hash"`
	ReviewHash          string `json:"review_hash"`
}

// ValidateEvaluationGovernanceBinding validates the shape of a binding before
// it is trusted by a split replay.  File contents are checked by the CLI
// helper, while this package keeps the serialized contract independently
// verifiable by other callers.
func ValidateEvaluationGovernanceBinding(binding *EvaluationGovernanceBinding) error {
	if binding == nil {
		return errors.New("evaluation governance binding is nil")
	}
	for name, value := range map[string]string{
		"manifest_sha256":       binding.ManifestSHA256,
		"manifest_payload_hash": binding.ManifestPayloadHash,
		"formal_sha256":         binding.FormalSHA256,
		"input_sha256":          binding.InputSHA256,
		"policy_hash":           binding.PolicyHash,
		"review_hash":           binding.ReviewHash,
	} {
		if !isLowerHexSHA256(strings.TrimSpace(value)) {
			return fmt.Errorf("governance binding %s must be a 64-character lowercase SHA-256", name)
		}
	}
	if strings.TrimSpace(binding.Pipeline) == "" {
		return errors.New("governance binding pipeline is required")
	}
	if strings.TrimSpace(binding.Version) == "" {
		return errors.New("governance binding version is required")
	}
	if binding.FormalRecords < 1 {
		return errors.New("governance binding formal_records must be positive")
	}
	return nil
}

var (
	ErrEvaluationArtifactByteLimit  = errors.New("evaluation split artifact byte limit exceeded")
	ErrEvaluationArtifactTokenLimit = errors.New("evaluation split artifact JSON token limit exceeded")
	ErrEvaluationArtifactDepthLimit = errors.New("evaluation split artifact JSON nesting limit exceeded")
	ErrEvaluationJSONLByteLimit     = errors.New("evaluation JSONL byte limit exceeded")
)

// ErrEvaluationRecordLimit indicates that a bounded evaluation stream reached
// its configured record limit. The records already delivered to the callback
// remain valid, but the caller must not treat the partial stream as a complete
// blind set.
var ErrEvaluationRecordLimit = errors.New("evaluation record limit exceeded")

// EvaluationLoadOptions controls the bounded JSONL loader. Sharding uses the
// same raw-line hash as the corpus loader, so a split and its blind replay can
// be run in separate processes without changing membership.
type EvaluationLoadOptions struct {
	MaxRecords      int
	MaxBytes        int64
	Shards          int
	Shard           int
	RequireGoverned bool
	// VerifyGovernanceProvenance re-reads each governed source referenced by a
	// row and binds its line hash and semantic fingerprint to the original
	// record. It is enabled automatically whenever RequireGoverned is true. If
	// RequireGoverned is false, the explicit field applies the complete governed
	// row contract and verifies every row that carries any provenance metadata;
	// a purely hand-authored row with no provenance fields remains allowed.
	VerifyGovernanceProvenance bool
}

// EvaluationLoadStats reports both the complete validated stream and the
// selected shard. Counts are deliberately separate: a shard report must never
// be mistaken for a global denominator.
type EvaluationLoadStats struct {
	NonEmptyLines   int `json:"non_empty_lines"`
	TotalRecords    int `json:"total_records"`
	SelectedRecords int `json:"selected_records"`
	SkippedOverlong int `json:"skipped_overlong"`
}

// ForEachEvaluationJSONL parses a finite, validated JSONL evaluation stream.
// Every bounded line is parsed before shard filtering, ensuring malformed data
// cannot disappear merely by selecting another shard. The callback is invoked
// only for records belonging to opts.Shard. A nil callback performs validation
// without retaining records.
func ForEachEvaluationJSONL(r io.Reader, opts EvaluationLoadOptions, fn func(EvaluationRecord) error) (EvaluationLoadStats, error) {
	if r == nil {
		return EvaluationLoadStats{}, errors.New("evaluation reader is nil")
	}
	if opts.MaxRecords == 0 {
		opts.MaxRecords = DefaultEvaluationMaxRecords
	}
	if opts.MaxRecords < 1 {
		return EvaluationLoadStats{}, errors.New("evaluation max records must be positive")
	}
	if opts.MaxRecords > MaxEvaluationRecords {
		return EvaluationLoadStats{}, fmt.Errorf("evaluation max records must not exceed %d", MaxEvaluationRecords)
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultEvaluationJSONLMaxBytes
	}
	if opts.MaxBytes < 1 {
		return EvaluationLoadStats{}, errors.New("evaluation max bytes must be positive")
	}
	if opts.MaxBytes > MaxEvaluationJSONLBytes {
		return EvaluationLoadStats{}, fmt.Errorf("evaluation max bytes must not exceed %d", MaxEvaluationJSONLBytes)
	}
	if opts.Shards == 0 {
		opts.Shards = 1
	}
	if err := ValidateShard(opts.Shards, opts.Shard); err != nil {
		return EvaluationLoadStats{}, err
	}
	stats := EvaluationLoadStats{}
	var provenance *evaluationProvenanceIndex
	if opts.RequireGoverned || opts.VerifyGovernanceProvenance {
		provenance = &evaluationProvenanceIndex{sources: make(map[string]*evaluationSourceIndex)}
	}
	reader := bufio.NewReaderSize(r, 64*1024)
	lineNo := 0
	var consumedBytes int64
	for {
		line, overlong, readBytes, readErr := readEvaluationLine(reader, corpusMaxLineBytes(), opts.MaxBytes-consumedBytes)
		consumedBytes += readBytes
		if errors.Is(readErr, ErrEvaluationJSONLByteLimit) {
			return stats, fmt.Errorf("%w: max %d bytes", ErrEvaluationJSONLByteLimit, opts.MaxBytes)
		}
		if len(line) > 0 || readErr == nil {
			lineNo++
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			stats.NonEmptyLines++
			if overlong || len(trimmed) > corpusMaxLineBytes() {
				stats.SkippedOverlong++
			} else {
				if !utf8.Valid(trimmed) {
					return stats, fmt.Errorf("line %d: invalid UTF-8", lineNo)
				}
				// Use the bounded scanner here, before unmarshalling. The legacy
				// corpus scanner is recursive without a depth/token budget and
				// would let a deeply nested line exhaust stack/CPU first.
				if err := validateJSONDocument(trimmed); err != nil {
					return stats, fmt.Errorf("line %d: %w", lineNo, err)
				}
				var record EvaluationRecord
				if err := json.Unmarshal(trimmed, &record); err != nil {
					return stats, fmt.Errorf("line %d: %w", lineNo, err)
				}
				metadataPresent := hasEvaluationGovernanceMetadata(record)
				requireGovernedRecord := opts.RequireGoverned || (opts.VerifyGovernanceProvenance && metadataPresent)
				if err := validateEvaluationRecordMode(record, SplitConfig{}, requireGovernedRecord); err != nil {
					return stats, fmt.Errorf("line %d: %w", lineNo, err)
				}
				if provenance != nil && (opts.RequireGoverned || metadataPresent) {
					if err := provenance.verify(record); err != nil {
						return stats, fmt.Errorf("line %d: %w", lineNo, err)
					}
				}
				if stats.TotalRecords >= opts.MaxRecords {
					return stats, fmt.Errorf("%w: max %d", ErrEvaluationRecordLimit, opts.MaxRecords)
				}
				stats.TotalRecords++
				if opts.Shards == 1 || ShardIndexForRaw(trimmed, opts.Shards) == opts.Shard {
					stats.SelectedRecords++
					if fn != nil {
						if err := fn(record); err != nil {
							return stats, err
						}
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return stats, nil
			}
			return stats, readErr
		}
	}
}

// hasEvaluationGovernanceMetadata distinguishes a genuinely hand-authored
// row from one that attempts to present itself as governed. When callers opt
// into provenance verification on an otherwise ungoverned stream, any partial
// provenance must fail closed rather than silently downgrading the artifact.
func hasEvaluationGovernanceMetadata(record EvaluationRecord) bool {
	return strings.TrimSpace(record.GovernancePath) != "" ||
		record.GovernanceLine != 0 ||
		strings.TrimSpace(record.RawHash) != "" ||
		strings.TrimSpace(record.Decision) != "" ||
		strings.TrimSpace(record.ReviewRuleVersion) != "" ||
		strings.TrimSpace(record.Reviewer) != "" ||
		strings.TrimSpace(record.ReviewReason) != "" ||
		strings.TrimSpace(record.ReviewedAt) != ""
}

// evaluationProvenanceIndex is a bounded, read-only index of the source lines
// referenced by governed evaluation rows. Keeping only hashes and the
// fingerprints parsed from each line avoids retaining request bodies twice,
// while still detecting both forged raw_hash values and case replacement.
type evaluationProvenanceIndex struct {
	sources map[string]*evaluationSourceIndex
}

type evaluationSourceIndex struct {
	lines map[int]evaluationProvenanceLine
}

type evaluationProvenanceLine struct {
	rawHash      string
	fingerprints map[string]struct{}
}

func (p *evaluationProvenanceIndex) verify(record EvaluationRecord) error {
	if p == nil {
		return nil
	}
	path := strings.TrimSpace(record.GovernancePath)
	if path == "" || record.GovernanceLine < 1 {
		return errors.New("governance provenance requires a source path and positive line")
	}
	key := canonicalCorpusPath(path)
	index, ok := p.sources[key]
	if !ok {
		loaded, err := loadEvaluationSourceIndex(path)
		if err != nil {
			return fmt.Errorf("verify governance provenance %q: %w", path, err)
		}
		index = loaded
		p.sources[key] = index
	}
	line, ok := index.lines[record.GovernanceLine]
	if !ok {
		return fmt.Errorf("governance provenance line %d is missing from %q", record.GovernanceLine, path)
	}
	if !strings.EqualFold(strings.TrimSpace(record.RawHash), line.rawHash) {
		return fmt.Errorf("governance raw_hash does not match %q line %d", path, record.GovernanceLine)
	}
	fingerprint := strings.ToLower(strings.TrimSpace(record.Fingerprint))
	if len(line.fingerprints) == 0 {
		return fmt.Errorf("governance source %q line %d is not an adaptable evaluation record", path, record.GovernanceLine)
	}
	if _, ok := line.fingerprints[fingerprint]; !ok {
		return fmt.Errorf("governance fingerprint does not match %q line %d", path, record.GovernanceLine)
	}
	return nil
}

func loadEvaluationSourceIndex(path string) (*evaluationSourceIndex, error) {
	if isRemoteCorpusPath(path) {
		return nil, errors.New("governance source must be a local file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("governance source must be a regular file")
	}
	var reader io.Reader = file
	var gz *gzip.Reader
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err = gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}
	index := &evaluationSourceIndex{lines: make(map[int]evaluationProvenanceLine)}
	// A forged governance_path must not turn provenance verification into an
	// unbounded second corpus load. Keep both decompressed bytes and physical
	// lines finite; the referenced line still gets the same exact hash check.
	counter := &countingReader{r: reader}
	limited := io.LimitReader(counter, MaxEvaluationJSONLBytes+1)
	br := bufio.NewReaderSize(limited, 64*1024)
	lineNo := 0
	for {
		line, overlong, readErr := readBoundedJSONLLine(br, corpusMaxLineBytes())
		if len(line) > 0 || readErr == nil {
			lineNo++
			if lineNo > MaxEvaluationRecords {
				return nil, fmt.Errorf("governance source %q exceeds %d lines", path, MaxEvaluationRecords)
			}
		}
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			entry := evaluationProvenanceLine{rawHash: hashBytes(line), fingerprints: make(map[string]struct{})}
			if !overlong && len(line) <= corpusMaxLineBytes() {
				for _, fingerprint := range fingerprintsForGovernanceLine(line) {
					entry.fingerprints[strings.ToLower(fingerprint)] = struct{}{}
				}
			}
			index.lines[lineNo] = entry
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			if counter.n > MaxEvaluationJSONLBytes {
				return nil, ErrEvaluationJSONLByteLimit
			}
			return nil, readErr
		}
	}
	if counter.n > MaxEvaluationJSONLBytes {
		return nil, ErrEvaluationJSONLByteLimit
	}
	return index, nil
}

// fingerprintsForGovernanceLine mirrors the governance adapter's supported
// wire forms. The semantic fingerprint excludes names, labels, and source
// family, so trying both payload truths is sufficient without knowing the
// source-side default-truth metadata.
func fingerprintsForGovernanceLine(line []byte) []string {
	seen := make(map[string]struct{}, 4)
	add := func(c Case) {
		if err := ValidateCase(c); err == nil {
			seen[strings.ToLower(CaseFingerprint(c))] = struct{}{}
		}
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(line, &shape) == nil && shape != nil {
		if hasJSONKey(shape, "target", "Target", "body", "Body", "header", "Header", "content_type", "ContentType", "source_family", "SourceFamily", "rationale", "Rationale") {
			var c Case
			if json.Unmarshal(line, &c) == nil {
				add(c)
			}
		}
		for _, truth := range []string{"benign", "attack"} {
			if parsed, err := parseRecord(line, 1, SourceSpec{Name: "provenance", DefaultTruth: truth}, "provenance"); err == nil {
				add(parsed.Case)
			}
		}
	} else {
		for _, truth := range []string{"benign", "attack"} {
			if parsed, err := parseRecord(line, 1, SourceSpec{Name: "provenance", DefaultTruth: truth}, "provenance"); err == nil {
				add(parsed.Case)
			}
		}
	}
	result := make([]string, 0, len(seen))
	for fingerprint := range seen {
		result = append(result, fingerprint)
	}
	return result
}

// LoadEvaluationJSONL is the slice-backed convenience form of
// ForEachEvaluationJSONL. It still enforces the finite default cap and the
// same validation/shard semantics.
func LoadEvaluationJSONL(r io.Reader, opts EvaluationLoadOptions) ([]EvaluationRecord, EvaluationLoadStats, error) {
	records := make([]EvaluationRecord, 0)
	stats, err := ForEachEvaluationJSONL(r, opts, func(record EvaluationRecord) error {
		records = append(records, record)
		return nil
	})
	return records, stats, err
}

// readEvaluationLine bounds retained input while consuming the complete
// physical line. This is intentionally independent of the corpus package's
// unexported reader so the evaluation loader remains a self-contained API.
func readEvaluationLine(reader *bufio.Reader, maxLine int, remainingBytes int64) ([]byte, bool, int64, error) {
	if reader == nil {
		return nil, false, 0, io.EOF
	}
	if maxLine < 1 {
		maxLine = 1
	}
	if remainingBytes < 0 {
		return nil, false, 0, ErrEvaluationJSONLByteLimit
	}
	if remainingBytes == 0 {
		// Permit an exact-budget stream to finish cleanly, but reject any
		// additional byte without retaining or parsing it.
		_, err := reader.ReadByte()
		if err == io.EOF {
			return nil, false, 0, io.EOF
		}
		if err == nil {
			return nil, false, 1, ErrEvaluationJSONLByteLimit
		}
		return nil, false, 0, err
	}
	const newlineAllowance = 2
	limit := maxLine + newlineAllowance
	line := make([]byte, 0, minEvaluationBufferCapacity(limit))
	overlong := false
	var consumed int64
	for {
		fragment, err := reader.ReadSlice('\n')
		consumed += int64(len(fragment))
		if consumed > remainingBytes {
			return nil, false, consumed, ErrEvaluationJSONLByteLimit
		}
		if len(fragment) > 0 && !overlong {
			remaining := limit - len(line)
			if remaining <= 0 {
				overlong = true
			} else if len(fragment) > remaining {
				line = append(line, fragment[:remaining]...)
				overlong = true
			} else {
				line = append(line, fragment...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) > maxLine {
			overlong = true
		}
		return line, overlong, consumed, err
	}
}

func minEvaluationBufferCapacity(limit int) int {
	if limit < 64*1024 {
		return limit
	}
	return 64 * 1024
}

// EvaluationRecord is the metadata envelope used by independent evaluation
// sets. The request itself must already have passed the corpus governance
// pipeline; this type only adds the grouping boundaries needed to prevent
// source, site, session, and temporal leakage between splits.
//
// The decoder accepts both an explicit {"case": {...}} envelope and the flat
// governance output shape. Grouping metadata is never included in a detector
// request and should contain stable pseudonyms rather than raw personal data.
type EvaluationRecord struct {
	ID          string    `json:"id,omitempty"`
	Case        Case      `json:"case"`
	Source      string    `json:"source"`
	Site        string    `json:"site"`
	Session     string    `json:"session"`
	Timestamp   time.Time `json:"timestamp"`
	Fingerprint string    `json:"fingerprint"`

	// Governance provenance is optional for hand-authored sidecars, but is a
	// known part of the formal governance output. Retaining it prevents strict
	// decoding from either rejecting a governed row or silently discarding the
	// audit trail when the row is copied into a split artifact.
	GovernancePath    string `json:"governance_path,omitempty"`
	GovernanceLine    int    `json:"governance_line,omitempty"`
	RawHash           string `json:"raw_hash,omitempty"`
	Decision          string `json:"decision,omitempty"`
	ReviewRuleVersion string `json:"review_rule_version,omitempty"`
	Reviewer          string `json:"reviewer,omitempty"`
	ReviewReason      string `json:"review_reason,omitempty"`
	ReviewedAt        string `json:"reviewed_at,omitempty"`
}

// UnmarshalJSON accepts the nested sidecar form and the flat formal artifact
// form without silently inventing session or time boundaries.
func (r *EvaluationRecord) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("nil evaluation record")
	}
	return unmarshalEvaluationRecord(data, false, r, nil)
}

// evaluationCaseJSONFields and evaluationRecordJSONFields are deliberately
// maintained as explicit allow-lists. encoding/json's DisallowUnknownFields
// cannot inspect a type that implements UnmarshalJSON, so without these lists
// a misspelled metadata or case field would be silently ignored.
var evaluationCaseJSONFields = map[string]struct{}{
	"name": {}, "Name": {},
	"source_family": {}, "SourceFamily": {},
	"label": {}, "Label": {},
	"category": {}, "Category": {},
	"method": {}, "Method": {},
	"target": {}, "Target": {},
	"content_type": {}, "ContentType": {},
	"body": {}, "Body": {},
	"header": {}, "Header": {},
	"rationale": {}, "Rationale": {},
}

var evaluationRecordJSONFields = map[string]struct{}{
	"id": {}, "ID": {}, "name": {}, "Name": {},
	"source": {}, "Source": {}, "governance_source": {}, "GovernanceSource": {},
	"site": {}, "Site": {}, "site_id": {}, "SiteID": {}, "host": {}, "Host": {},
	"session": {}, "Session": {}, "session_id": {}, "SessionID": {},
	"timestamp": {}, "Timestamp": {}, "fingerprint": {}, "Fingerprint": {}, "case": {}, "Case": {},
	// Formal governance rows are flat and carry these audit fields. They are
	// preserved in EvaluationRecord rather than treated as unknown input.
	"governance_path": {}, "GovernancePath": {}, "governance_line": {}, "GovernanceLine": {}, "raw_hash": {}, "RawHash": {},
	"decision": {}, "Decision": {}, "review_rule_version": {}, "ReviewRuleVersion": {}, "reviewer": {}, "Reviewer": {},
	"review_reason": {}, "ReviewReason": {}, "reviewed_at": {}, "ReviewedAt": {},
}

var assignedEvaluationJSONFields = map[string]struct{}{
	"split": {}, "Split": {}, "group": {}, "Group": {},
}

type evaluationRecordRaw struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Source            string          `json:"source"`
	GovernanceSource  string          `json:"governance_source"`
	Site              string          `json:"site"`
	SiteID            string          `json:"site_id"`
	Host              string          `json:"host"`
	Session           string          `json:"session"`
	SessionID         string          `json:"session_id"`
	Timestamp         string          `json:"timestamp"`
	Fingerprint       string          `json:"fingerprint"`
	Case              json.RawMessage `json:"case"`
	GovernancePath    string          `json:"governance_path"`
	GovernanceLine    int             `json:"governance_line"`
	RawHash           string          `json:"raw_hash"`
	Decision          string          `json:"decision"`
	ReviewRuleVersion string          `json:"review_rule_version"`
	Reviewer          string          `json:"reviewer"`
	ReviewReason      string          `json:"review_reason"`
	ReviewedAt        string          `json:"reviewed_at"`
}

type assignedEvaluationMeta struct {
	Split EvaluationSplit `json:"split"`
	Group string          `json:"group"`
}

// unmarshalEvaluationRecord is shared by plain and assigned rows. The latter
// adds split/group to the allow-list but otherwise follows exactly the same
// strict envelope and case decoding path.
func unmarshalEvaluationRecord(data []byte, allowAssignment bool, record *EvaluationRecord, meta *assignedEvaluationMeta) error {
	allowed := mergeJSONFieldSets(evaluationRecordJSONFields, evaluationCaseJSONFields)
	if allowAssignment {
		allowed = mergeJSONFieldSets(allowed, assignedEvaluationJSONFields)
	}
	object, err := strictJSONObject(data, allowed, "evaluation record")
	if err != nil {
		return err
	}
	if err := validateEvaluationCaseAliases(object); err != nil {
		return err
	}

	// A nested envelope and flat case fields are two distinct wire formats.
	// Accepting both would make one representation silently override the other.
	caseRaw, hasCase := jsonObjectField(object, "case")
	if hasCase {
		caseFields := normalizedJSONFieldSet(evaluationCaseJSONFields)
		for key := range object {
			if _, isCaseField := caseFields[strings.ToLower(key)]; isCaseField && strings.ToLower(key) != "name" {
				return fmt.Errorf("evaluation record cannot combine case envelope with flat case field %q", key)
			}
		}
	}

	var raw evaluationRecordRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var c Case
	if hasCase && !bytes.Equal(bytes.TrimSpace(caseRaw), []byte("null")) {
		c, err = unmarshalEvaluationCase(caseRaw)
		if err != nil {
			return fmt.Errorf("evaluation case: %w", err)
		}
	} else {
		// strictJSONObject has already checked the full envelope. Decode the
		// flat form through Case so metadata fields are ignored only after the
		// explicit envelope allow-list has accepted them.
		if err := json.Unmarshal(data, &c); err != nil {
			return fmt.Errorf("evaluation flat case: %w", err)
		}
	}
	if err := ValidateCase(c); err != nil {
		return err
	}

	source, err := selectEvaluationAlias(object, "source", "governance_source")
	if err != nil {
		return err
	}
	site, err := selectEvaluationAlias(object, "site", "site_id", "host")
	if err != nil {
		return err
	}
	session, err := selectEvaluationAlias(object, "session", "session_id")
	if err != nil {
		return err
	}
	source = firstNonEmpty(source, c.SourceFamily)
	site = firstNonEmpty(site, siteFromCase(c))
	// Formal governance rows do not carry request-session fields. Derive a
	// stable pseudonymous snapshot/session boundary from their source path so
	// they remain groupable without exposing a local path in the artifact.
	if strings.TrimSpace(site) == "" && strings.TrimSpace(source) != "" && strings.TrimSpace(raw.GovernancePath) != "" {
		site = source
	}
	if strings.TrimSpace(session) == "" && strings.TrimSpace(raw.GovernancePath) != "" {
		session = "governance:" + hashBytes([]byte(strings.TrimSpace(source)+"\x00"+strings.TrimSpace(raw.GovernancePath)))
	}
	timestamp, err := parseEvaluationTimestamp(raw.Timestamp)
	if err != nil {
		return err
	}
	fingerprint := strings.TrimSpace(raw.Fingerprint)
	if fingerprint == "" {
		fingerprint = CaseFingerprint(c)
	}
	id := firstNonEmpty(raw.ID, raw.Name, c.Name, fingerprint)
	*record = EvaluationRecord{
		ID: id, Case: c,
		Source: strings.TrimSpace(source), Site: strings.TrimSpace(site), Session: strings.TrimSpace(session),
		Timestamp: timestamp, Fingerprint: fingerprint,
		GovernancePath: raw.GovernancePath, GovernanceLine: raw.GovernanceLine,
		RawHash: raw.RawHash, Decision: raw.Decision, ReviewRuleVersion: raw.ReviewRuleVersion,
		Reviewer: raw.Reviewer, ReviewReason: raw.ReviewReason, ReviewedAt: raw.ReviewedAt,
	}
	if allowAssignment && meta != nil {
		var assignment assignedEvaluationMeta
		if err := json.Unmarshal(data, &assignment); err != nil {
			return err
		}
		*meta = assignment
	}
	return nil
}

func unmarshalEvaluationCase(data []byte) (Case, error) {
	object, err := strictJSONObject(data, evaluationCaseJSONFields, "evaluation case")
	if err != nil {
		return Case{}, err
	}
	if err := validateEvaluationCaseAliases(object); err != nil {
		return Case{}, err
	}
	var c Case
	if err := json.Unmarshal(data, &c); err != nil {
		return Case{}, err
	}
	return c, nil
}

func validateEvaluationCaseAliases(object map[string]json.RawMessage) error {
	groups := [][]string{
		{"name", "Name"},
		{"source_family", "SourceFamily"},
		{"label", "Label"},
		{"category", "Category"},
		{"method", "Method"},
		{"target", "Target"},
		{"content_type", "ContentType"},
		{"body", "Body"},
		{"header", "Header"},
		{"rationale", "Rationale"},
	}
	for _, group := range groups {
		present := ""
		for key := range object {
			if !jsonFieldEquivalent(key, group[0]) {
				continue
			}
			if present != "" {
				return fmt.Errorf("evaluation case contains multiple aliases for %q (%s and %s)", group[0], present, key)
			}
			present = key
		}
	}
	return nil
}

func mergeJSONFieldSets(sets ...map[string]struct{}) map[string]struct{} {
	merged := make(map[string]struct{})
	for _, set := range sets {
		for key := range set {
			merged[key] = struct{}{}
		}
	}
	return merged
}

func normalizedJSONFieldSet(fields map[string]struct{}) map[string]struct{} {
	normalized := make(map[string]struct{}, len(fields))
	for field := range fields {
		normalized[strings.ToLower(field)] = struct{}{}
	}
	return normalized
}

func jsonObjectField(object map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func selectEvaluationAlias(object map[string]json.RawMessage, names ...string) (string, error) {
	var selected string
	var selectedName string
	for _, name := range names {
		for key, raw := range object {
			if !jsonFieldEquivalent(key, name) {
				continue
			}
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return "", fmt.Errorf("evaluation field %q: %w", key, err)
			}
			if selectedName != "" {
				return "", fmt.Errorf("evaluation record contains multiple aliases for %q (%s and %s)", names[0], selectedName, key)
			}
			selected, selectedName = value, key
		}
	}
	return selected, nil
}

func jsonFieldEquivalent(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	return strings.EqualFold(strings.ReplaceAll(a, "_", ""), strings.ReplaceAll(b, "_", ""))
}

func strictJSONObject(data []byte, allowed map[string]struct{}, what string) (map[string]json.RawMessage, error) {
	if err := validateJSONDocument(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("%s must be a JSON object", what)
	}
	allowedNormalized := normalizedJSONFieldSet(allowed)
	for key := range object {
		if _, ok := allowedNormalized[strings.ToLower(key)]; !ok {
			return nil, fmt.Errorf("%s has unknown field %q", what, key)
		}
	}
	return object, nil
}

// validateJSONDocument performs duplicate-member and trailing-value checks
// without relying on encoding/json's last-value-wins object semantics.
func validateJSONDocument(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	budget := jsonScanBudget{
		maxDepth:  DefaultEvaluationArtifactMaxDepth,
		maxTokens: DefaultEvaluationArtifactMaxTokens,
	}
	duplicate, err := scanEvaluationJSONValue(decoder, 0, &budget)
	if err != nil {
		return err
	}
	if err := ensureEvaluationJSONEOF(decoder); err != nil {
		return err
	}
	if duplicate {
		return errors.New("duplicate JSON object key")
	}
	return nil
}

type jsonScanBudget struct {
	maxDepth  int
	maxTokens int
	tokens    int
}

func (b *jsonScanBudget) consume(depth int) error {
	if depth > b.maxDepth {
		return ErrEvaluationArtifactDepthLimit
	}
	b.tokens++
	if b.maxTokens > 0 && b.tokens > b.maxTokens {
		return ErrEvaluationArtifactTokenLimit
	}
	return nil
}

// scanEvaluationJSONValue validates duplicate members while enforcing a
// finite recursion and token budget. JSON strings are single tokens, so large
// bodies are governed by the separate artifact byte limit.
func scanEvaluationJSONValue(decoder *json.Decoder, depth int, budget *jsonScanBudget) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if err := budget.consume(depth); err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		duplicate := false
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			if err := budget.consume(depth + 1); err != nil {
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
			childDuplicate, err := scanEvaluationJSONValue(decoder, depth+1, budget)
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
			childDuplicate, err := scanEvaluationJSONValue(decoder, depth+1, budget)
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

func parseEvaluationTimestamp(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	return t.UTC(), nil
}

func siteFromCase(c Case) string {
	if parsed, err := url.Parse(strings.TrimSpace(c.Target)); err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Host)
	}
	for name, value := range c.Header {
		if strings.EqualFold(name, "host") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

// CaseFingerprint returns the same request-level semantic fingerprint used by
// governance. Keeping one implementation prevents a blind-set splitter from
// treating a duplicate request as independent merely because its wrapper
// metadata differs.
func CaseFingerprint(c Case) string { return semanticFingerprint(c) }

// EvaluationSplit names the three non-overlapping evaluation partitions.
type EvaluationSplit string

const (
	SplitTrain      EvaluationSplit = "train"
	SplitValidation EvaluationSplit = "validation"
	SplitBlind      EvaluationSplit = "blind"
)

// SplitConfig controls deterministic group-aware partitioning. If no time
// boundary is configured, groups are assigned by a stable hash using the two
// fractions. If one or both boundaries are configured, every member of a
// source/site/session group must fit wholly within one time interval.
type SplitConfig struct {
	Seed               string     `json:"seed,omitempty"`
	ValidationFraction float64    `json:"validation_fraction,omitempty"`
	BlindFraction      float64    `json:"blind_fraction,omitempty"`
	ValidationStart    *time.Time `json:"validation_start,omitempty"`
	BlindStart         *time.Time `json:"blind_start,omitempty"`
}

// UnmarshalJSON makes split configuration strict even when it is decoded as a
// child of a type that uses a custom decoder. In particular, duplicate keys
// such as {"seed":"a","seed":"b"} must not be reduced to the last value.
func (c *SplitConfig) UnmarshalJSON(data []byte) error {
	if c == nil {
		return errors.New("nil split config")
	}
	if err := validateJSONDocument(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	type splitConfigAlias SplitConfig
	var decoded splitConfigAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*c = SplitConfig(decoded)
	return nil
}

const (
	// EvaluationSplitArtifactVersion is kept stable for the first serialized
	// contract. AssignmentPolicy below makes the assignment algorithm explicit,
	// so a future policy can coexist without silently reinterpreting old files.
	EvaluationSplitArtifactVersion = "evaluation-split-v1"
	// EvaluationSplitAssignmentPolicy identifies the component hash assignment
	// plus deterministic empty-partition repair used by new artifacts.
	EvaluationSplitAssignmentPolicy       = "group-hash-repair-v1"
	legacyEvaluationSplitAssignmentPolicy = "group-hash-v1"
	// evaluationSplitRecordsDigestDomain separates the record-list digest from
	// every other SHA-256 use. The JSON projection behind this v1 domain is
	// frozen; changing its field semantics requires a new domain/version.
	evaluationSplitRecordsDigestDomain = "evaluation-split-records-v1\n"
)

// EvaluationSplitArtifact is the deterministic, auditable output consumed by
// later training/evaluation stages. Records retain their governance envelope;
// grouping metadata is pseudonymous and never needs to be sent to a detector.
type EvaluationSplitArtifact struct {
	Version          string `json:"version"`
	AssignmentPolicy string `json:"assignment_policy,omitempty"`
	// Governed is true only when every input row carried validated governance
	// provenance. Consumers may use ungoverned artifacts for local smoke tests,
	// but they must never certify them as blind quality evidence.
	Governed     bool                         `json:"governed,omitempty"`
	Governance   *EvaluationGovernanceBinding `json:"governance,omitempty"`
	Config       SplitConfig                  `json:"config"`
	InputRecords int                          `json:"input_records"`
	LoadStats    EvaluationLoadStats          `json:"load_stats,omitempty"`
	Summary      SplitSummary                 `json:"summary"`
	// RecordsSHA256 binds the ordered, complete assigned-record list, including
	// every case field, governance identity, and the split/group assignment.
	// Governed artifacts require it; ungoverned artifacts may omit it only for
	// compatibility with historical local smoke-test files.
	RecordsSHA256 string                     `json:"records_sha256,omitempty"`
	Records       []AssignedEvaluationRecord `json:"records"`
}

// UnmarshalJSON validates the whole document before decoding any assignment.
// This closes the gap where DisallowUnknownFields would otherwise stop at the
// custom AssignedEvaluationRecord decoder and where encoding/json would keep
// only the last duplicate object member.
func (a *EvaluationSplitArtifact) UnmarshalJSON(data []byte) error {
	if a == nil {
		return errors.New("nil evaluation split artifact")
	}
	if len(data) > DefaultEvaluationArtifactMaxBytes {
		return ErrEvaluationArtifactByteLimit
	}
	if err := validateJSONDocument(data); err != nil {
		return err
	}
	if count, err := countArtifactRecords(data, MaxEvaluationRecords); err != nil {
		return err
	} else if count > MaxEvaluationRecords {
		return fmt.Errorf("evaluation split artifact has %d records; max %d", count, MaxEvaluationRecords)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	type artifactAlias EvaluationSplitArtifact
	var decoded artifactAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := ensureEvaluationJSONEOF(decoder); err != nil {
		return err
	}
	if err := validateEvaluationSplitArtifact(EvaluationSplitArtifact(decoded), true); err != nil {
		return err
	}
	*a = EvaluationSplitArtifact(decoded)
	return nil
}

// LoadEvaluationSplitArtifact decodes one complete JSON artifact and applies
// the same structural checks used by the detector-facing replay command. The
// record cap is checked before any caller selects a partition so an oversized
// artifact cannot be mistaken for a small blind set.
func LoadEvaluationSplitArtifact(r io.Reader, maxRecords int) (EvaluationSplitArtifact, error) {
	var artifact EvaluationSplitArtifact
	if r == nil {
		return artifact, errors.New("evaluation split artifact reader is nil")
	}
	if maxRecords == 0 {
		maxRecords = DefaultEvaluationMaxRecords
	}
	if maxRecords < 1 {
		return artifact, errors.New("evaluation split artifact max records must be positive")
	}
	if maxRecords > MaxEvaluationRecords {
		return artifact, fmt.Errorf("evaluation split artifact max records must not exceed %d", MaxEvaluationRecords)
	}
	data, err := io.ReadAll(io.LimitReader(r, DefaultEvaluationArtifactMaxBytes+1))
	if err != nil {
		return artifact, fmt.Errorf("read evaluation split artifact: %w", err)
	}
	if len(data) > DefaultEvaluationArtifactMaxBytes {
		return artifact, ErrEvaluationArtifactByteLimit
	}
	if err := validateJSONDocument(data); err != nil {
		return artifact, fmt.Errorf("parse evaluation split artifact: %w", err)
	}
	if count, err := countArtifactRecords(data, maxRecords); err != nil {
		return artifact, err
	} else if count > maxRecords {
		return artifact, fmt.Errorf("evaluation split artifact has %d records; max %d", count, maxRecords)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&artifact); err != nil {
		return artifact, fmt.Errorf("parse evaluation split artifact: %w", err)
	}
	if err := ensureEvaluationJSONEOF(decoder); err != nil {
		return artifact, fmt.Errorf("parse evaluation split artifact: %w", err)
	}
	if artifact.InputRecords > maxRecords || len(artifact.Records) > maxRecords {
		return artifact, fmt.Errorf("evaluation split artifact has %d records; max %d", artifact.InputRecords, maxRecords)
	}
	if err := validateEvaluationSplitArtifact(artifact, true); err != nil {
		return artifact, err
	}
	return artifact, nil
}

func ensureEvaluationJSONEOF(decoder *json.Decoder) error {
	if decoder == nil {
		return io.EOF
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// countArtifactRecords walks only the top-level artifact envelope and counts
// records without decoding them into a slice. This check runs before the
// artifact unmarshal, preventing an oversized records array from being
// materialized merely to discover that it exceeds maxRecords.
func countArtifactRecords(data []byte, maxRecords int) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return 0, fmt.Errorf("parse evaluation split artifact: %w", err)
	}
	if token != json.Delim('{') {
		return 0, errors.New("evaluation split artifact must be a JSON object")
	}
	count := 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return 0, fmt.Errorf("parse evaluation split artifact: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return 0, errors.New("evaluation split artifact object key is not a string")
		}
		if strings.EqualFold(key, "records") {
			value, err := decoder.Token()
			if err != nil {
				return 0, fmt.Errorf("parse evaluation split artifact records: %w", err)
			}
			if value != json.Delim('[') {
				return 0, errors.New("evaluation split artifact records must be an array")
			}
			for decoder.More() {
				count++
				if count > maxRecords {
					return count, fmt.Errorf("%w: max %d", ErrEvaluationRecordLimit, maxRecords)
				}
				if err := skipEvaluationJSONValue(decoder); err != nil {
					return 0, fmt.Errorf("parse evaluation split artifact records: %w", err)
				}
			}
			if _, err := decoder.Token(); err != nil {
				return 0, fmt.Errorf("parse evaluation split artifact records: %w", err)
			}
			continue
		}
		if err := skipEvaluationJSONValue(decoder); err != nil {
			return 0, fmt.Errorf("parse evaluation split artifact: %w", err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return 0, fmt.Errorf("parse evaluation split artifact: %w", err)
	}
	return count, nil
}

func skipEvaluationJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			for decoder.More() {
				if _, err := decoder.Token(); err != nil {
					return err
				}
				if err := skipEvaluationJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		case '[':
			for decoder.More() {
				if err := skipEvaluationJSONValue(decoder); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		}
	}
	return err
}

// BuildEvaluationSplit validates and assigns a complete record set in one
// operation. Keeping this constructor in the security package makes the CLI
// and other local tooling share exactly the same leakage checks.
func BuildEvaluationSplit(records []EvaluationRecord, cfg SplitConfig) (EvaluationSplitArtifact, error) {
	normalized, err := normalizeSplitConfig(cfg)
	if err != nil {
		return EvaluationSplitArtifact{}, err
	}
	assigned, summary, err := GroupAwareSplit(records, normalized)
	if err != nil {
		return EvaluationSplitArtifact{}, err
	}
	recordsSHA256, err := EvaluationSplitRecordsSHA256(assigned)
	if err != nil {
		return EvaluationSplitArtifact{}, fmt.Errorf("hash evaluation split records: %w", err)
	}
	return EvaluationSplitArtifact{
		Version:          EvaluationSplitArtifactVersion,
		AssignmentPolicy: EvaluationSplitAssignmentPolicy,
		Governed:         evaluationRecordsGoverned(records),
		Config:           normalized,
		InputRecords:     len(records),
		LoadStats: EvaluationLoadStats{
			// A slice-backed constructor has no physical-line information, but
			// it still represents a complete validated stream with one selected
			// record per input item.
			NonEmptyLines:   len(records),
			TotalRecords:    len(records),
			SelectedRecords: len(records),
		},
		Summary:       summary,
		RecordsSHA256: recordsSHA256,
		Records:       assigned,
	}, nil
}

func evaluationRecordsGoverned(records []EvaluationRecord) bool {
	if len(records) == 0 {
		return false
	}
	for _, record := range records {
		if strings.TrimSpace(record.GovernancePath) == "" || record.GovernanceLine < 1 ||
			!isLowerHexSHA256(strings.TrimSpace(record.RawHash)) {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(record.Decision)) {
		case "auto":
		case "approve":
			if strings.TrimSpace(record.ReviewRuleVersion) == "" || strings.TrimSpace(record.Reviewer) == "" || strings.TrimSpace(record.ReviewedAt) == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// AssignedEvaluationRecord binds one governed record to a split and an
// immutable connected-component identifier. The component ID is a hash of
// grouping keys, not raw request content.
type AssignedEvaluationRecord struct {
	EvaluationRecord
	Split EvaluationSplit `json:"split"`
	Group string          `json:"group"`
}

// MarshalJSON is explicit because EvaluationRecord has a custom
// UnmarshalJSON method. Without this method that promoted decoder would cause
// encoding/json to flatten/lose the split and group fields on a round trip.
// This exact v1 field projection, including Case's current JSON fields, is also
// the input to records_sha256 and must not change without introducing a new
// digest domain and artifact contract.
func (r AssignedEvaluationRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                string          `json:"id,omitempty"`
		Case              Case            `json:"case"`
		Source            string          `json:"source"`
		Site              string          `json:"site"`
		Session           string          `json:"session"`
		Timestamp         time.Time       `json:"timestamp,omitempty"`
		Fingerprint       string          `json:"fingerprint"`
		GovernancePath    string          `json:"governance_path,omitempty"`
		GovernanceLine    int             `json:"governance_line,omitempty"`
		RawHash           string          `json:"raw_hash,omitempty"`
		Decision          string          `json:"decision,omitempty"`
		ReviewRuleVersion string          `json:"review_rule_version,omitempty"`
		Reviewer          string          `json:"reviewer,omitempty"`
		ReviewReason      string          `json:"review_reason,omitempty"`
		ReviewedAt        string          `json:"reviewed_at,omitempty"`
		Split             EvaluationSplit `json:"split"`
		Group             string          `json:"group"`
	}{
		ID: r.ID, Case: r.Case, Source: r.Source, Site: r.Site, Session: r.Session,
		Timestamp: r.Timestamp, Fingerprint: r.Fingerprint,
		GovernancePath: r.GovernancePath, GovernanceLine: r.GovernanceLine, RawHash: r.RawHash,
		Decision: r.Decision, ReviewRuleVersion: r.ReviewRuleVersion, Reviewer: r.Reviewer,
		ReviewReason: r.ReviewReason, ReviewedAt: r.ReviewedAt,
		Split: r.Split, Group: r.Group,
	})
}

// UnmarshalJSON restores both the evaluation envelope and assignment fields.
// EvaluationRecord.UnmarshalJSON remains the single parser for flat and
// nested case shapes, while this small side decode captures the assignment
// metadata that would otherwise be swallowed by method promotion.
func (r *AssignedEvaluationRecord) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("nil assigned evaluation record")
	}
	var base EvaluationRecord
	var meta assignedEvaluationMeta
	if err := unmarshalEvaluationRecord(data, true, &base, &meta); err != nil {
		return err
	}
	*r = AssignedEvaluationRecord{EvaluationRecord: base, Split: meta.Split, Group: meta.Group}
	return nil
}

// EvaluationSplitRecordsSHA256 returns the deterministic, domain-separated
// SHA-256 identity of the ordered assigned-record list. The v1 projection is
// frozen to AssignedEvaluationRecord.MarshalJSON and Case's current JSON
// fields; future field semantics must use a new digest domain/version rather
// than reinterpreting an existing hash. encoding/json sorts string map keys,
// keeping request headers stable across processes regardless of iteration
// order.
func EvaluationSplitRecordsSHA256(records []AssignedEvaluationRecord) (string, error) {
	encoded, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = io.WriteString(h, evaluationSplitRecordsDigestDomain)
	_, _ = h.Write(encoded)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// SplitSummary exposes counts and grouping diagnostics without retaining raw
// payloads in a report.
type SplitSummary struct {
	Train      int `json:"train"`
	Validation int `json:"validation"`
	Blind      int `json:"blind"`
	Groups     int `json:"groups"`
	// Repaired records whether deterministic component moves were needed to
	// populate a requested fractional partition. It is an audit signal, not
	// evidence that the resulting partition is statistically independent.
	Repaired bool `json:"repaired,omitempty"`
}

// Count returns the number of records assigned to one named partition.
func (s SplitSummary) Count(split EvaluationSplit) int {
	switch split {
	case SplitTrain:
		return s.Train
	case SplitValidation:
		return s.Validation
	case SplitBlind:
		return s.Blind
	default:
		return 0
	}
}

// GroupAwareSplit validates records, joins any records sharing a source,
// site, session, or request fingerprint, and assigns each connected component
// atomically. Consequently no grouping key can straddle train, validation,
// and blind partitions.
func GroupAwareSplit(records []EvaluationRecord, cfg SplitConfig) ([]AssignedEvaluationRecord, SplitSummary, error) {
	return groupAwareSplit(records, cfg, true)
}

// groupAwareSplit contains the implementation shared by current artifacts and
// the legacy v1 compatibility path. The latter intentionally omits the repair
// pass so an older artifact with an empty fractional partition can still be
// verified against the policy that produced it.
func groupAwareSplit(records []EvaluationRecord, cfg SplitConfig, repair bool) ([]AssignedEvaluationRecord, SplitSummary, error) {
	if len(records) == 0 {
		return nil, SplitSummary{}, errors.New("evaluation set is empty")
	}
	cfg, err := normalizeSplitConfig(cfg)
	if err != nil {
		return nil, SplitSummary{}, err
	}
	for i := range records {
		if err := validateEvaluationRecord(records[i], cfg); err != nil {
			return nil, SplitSummary{}, fmt.Errorf("record %d: %w", i, err)
		}
	}
	seenFingerprints := make(map[string]int, len(records))
	for i, record := range records {
		fingerprint := strings.ToLower(strings.TrimSpace(record.Fingerprint))
		if previous, ok := seenFingerprints[fingerprint]; ok {
			return nil, SplitSummary{}, fmt.Errorf("records %d and %d duplicate fingerprint %s; deduplicate before splitting", previous, i, record.Fingerprint)
		}
		seenFingerprints[fingerprint] = i
	}

	uf := newUnionFind(len(records))
	byKey := make(map[string]int, len(records)*4)
	for i, record := range records {
		for _, key := range evaluationGroupKeys(record) {
			if previous, ok := byKey[key]; ok {
				uf.union(i, previous)
			} else {
				byKey[key] = i
			}
		}
	}

	groups := make(map[int][]int)
	for i := range records {
		root := uf.find(i)
		groups[root] = append(groups[root], i)
	}
	roots := make([]int, 0, len(groups))
	for root := range groups {
		roots = append(roots, root)
	}
	sort.Ints(roots)

	components := make([]evaluationComponentAssignment, 0, len(roots))
	for _, root := range roots {
		indices := groups[root]
		sort.Ints(indices)
		groupID := evaluationComponentID(records, indices)
		split, err := splitForGroup(records, indices, cfg, groupID)
		if err != nil {
			return nil, SplitSummary{}, fmt.Errorf("group %s: %w", groupID, err)
		}
		components = append(components, evaluationComponentAssignment{
			indices: indices,
			groupID: groupID,
			split:   split,
			rank:    evaluationGroupHash(cfg.Seed, groupID),
		})
	}
	repaired := false
	if repair && cfg.ValidationStart == nil && cfg.BlindStart == nil {
		// A component is the smallest unit that can be moved without violating
		// leakage isolation. Hashing remains the primary assignment; this pass
		// only repairs an empty requested partition when enough components exist
		// to make that repair possible. Tiny one-component smoke fixtures keep
		// their historical, necessarily incomplete assignment instead of being
		// rejected solely for lacking independent groups.
		var repairErr error
		repaired, repairErr = repairEmptyFractionalSplits(components, records, cfg)
		if repairErr != nil {
			return nil, SplitSummary{}, repairErr
		}
	}

	assigned := make([]AssignedEvaluationRecord, len(records))
	summary := SplitSummary{Repaired: repaired}
	for _, component := range components {
		for _, index := range component.indices {
			assigned[index] = AssignedEvaluationRecord{
				EvaluationRecord: records[index],
				Split:            component.split,
				Group:            component.groupID,
			}
			switch component.split {
			case SplitTrain:
				summary.Train++
			case SplitValidation:
				summary.Validation++
			case SplitBlind:
				summary.Blind++
			}
		}
		summary.Groups++
	}
	if err := ValidateEvaluationSplit(assigned); err != nil {
		return nil, SplitSummary{}, err
	}
	return assigned, summary, nil
}

// evaluationComponentAssignment keeps the split decision separate from the
// input record indexes. The latter are retained in input order for the output
// artifact, while rank is stable across input order and is used only for
// deterministic empty-partition repair.
type evaluationComponentAssignment struct {
	indices []int
	groupID string
	split   EvaluationSplit
	rank    uint64
}

// repairEmptyFractionalSplits repairs only the degenerate case where a
// positive-fraction partition received no connected component from the primary
// hash assignment. Moving a complete component preserves the source/site/
// session/fingerprint leakage invariant while making small, otherwise unusable
// evaluation snapshots replayable. The cost function chooses the move that is
// closest to the requested record fractions; all ties use the stable group
// hash and id, so the result is reproducible and independent of input order.
func repairEmptyFractionalSplits(components []evaluationComponentAssignment, records []EvaluationRecord, cfg SplitConfig) (bool, error) {
	requested := []EvaluationSplit{SplitTrain}
	if cfg.ValidationFraction > 0 {
		requested = append(requested, SplitValidation)
	}
	if cfg.BlindFraction > 0 {
		requested = append(requested, SplitBlind)
	}
	if len(components) < len(requested) {
		return false, nil
	}

	// Keep target order explicit rather than relying on map iteration. Blind is
	// repaired first because it is the immutable holdout; validation and train
	// follow in that order when they are also empty.
	targets := []EvaluationSplit{SplitBlind, SplitValidation, SplitTrain}
	counts := make(map[EvaluationSplit]int, len(requested))
	recordCounts := make(map[EvaluationSplit]int, len(requested))
	for _, component := range components {
		counts[component.split]++
		recordCounts[component.split] += len(component.indices)
	}
	totalRecords := len(records)
	repaired := false
	for _, target := range targets {
		if !containsEvaluationSplit(requested, target) || counts[target] > 0 {
			continue
		}
		best := -1
		bestCost := math.Inf(1)
		bestRank := ^uint64(0)
		bestGroup := ""
		for i := range components {
			from := components[i].split
			if counts[from] <= 1 {
				continue
			}
			before := components[i].split
			components[i].split = target
			counts[from]--
			counts[target]++
			recordCounts[from] -= len(components[i].indices)
			recordCounts[target] += len(components[i].indices)
			cost := fractionalSplitCost(recordCounts, totalRecords, cfg, requested)
			components[i].split = before
			counts[from]++
			counts[target]--
			recordCounts[from] += len(components[i].indices)
			recordCounts[target] -= len(components[i].indices)
			if cost < bestCost || (cost == bestCost && (components[i].rank < bestRank || (components[i].rank == bestRank && components[i].groupID < bestGroup))) {
				best = i
				bestCost = cost
				bestRank = components[i].rank
				bestGroup = components[i].groupID
			}
		}
		if best < 0 {
			return repaired, fmt.Errorf("fractional split cannot create non-empty %s partition from %d connected component(s)", target, len(components))
		}
		from := components[best].split
		components[best].split = target
		counts[from]--
		counts[target]++
		recordCounts[from] -= len(components[best].indices)
		recordCounts[target] += len(components[best].indices)
		repaired = true
	}
	return repaired, nil
}

func containsEvaluationSplit(splits []EvaluationSplit, wanted EvaluationSplit) bool {
	for _, split := range splits {
		if split == wanted {
			return true
		}
	}
	return false
}

func fractionalSplitCost(recordCounts map[EvaluationSplit]int, totalRecords int, cfg SplitConfig, requested []EvaluationSplit) float64 {
	if totalRecords < 1 {
		return math.Inf(1)
	}
	cost := 0.0
	for _, split := range requested {
		fraction := 1 - cfg.ValidationFraction - cfg.BlindFraction
		switch split {
		case SplitValidation:
			fraction = cfg.ValidationFraction
		case SplitBlind:
			fraction = cfg.BlindFraction
		}
		target := fraction * float64(totalRecords)
		cost += math.Abs(float64(recordCounts[split]) - target)
	}
	return cost
}

func normalizeSplitConfig(cfg SplitConfig) (SplitConfig, error) {
	if cfg.ValidationStart != nil || cfg.BlindStart != nil {
		// Fractions and temporal boundaries describe different partitioning
		// contracts. Silently preferring one makes a configuration review nearly
		// impossible, so require callers to choose exactly one strategy.
		if cfg.ValidationFraction != 0 || cfg.BlindFraction != 0 {
			return SplitConfig{}, errors.New("fractional and time-boundary split settings cannot be combined")
		}
	}
	if cfg.ValidationFraction == 0 && cfg.BlindFraction == 0 && cfg.ValidationStart == nil && cfg.BlindStart == nil {
		cfg.ValidationFraction = 0.2
		cfg.BlindFraction = 0.2
	}
	if math.IsNaN(cfg.ValidationFraction) || math.IsInf(cfg.ValidationFraction, 0) ||
		math.IsNaN(cfg.BlindFraction) || math.IsInf(cfg.BlindFraction, 0) ||
		cfg.ValidationFraction < 0 || cfg.BlindFraction < 0 || cfg.ValidationFraction+cfg.BlindFraction >= 1 {
		return SplitConfig{}, errors.New("validation and blind fractions must be non-negative and sum to less than one")
	}
	if cfg.ValidationStart != nil && cfg.BlindStart != nil && !cfg.ValidationStart.Before(*cfg.BlindStart) {
		return SplitConfig{}, errors.New("validation_start must be before blind_start")
	}
	if cfg.Seed == "" {
		cfg.Seed = "cheesewaf-evaluation-v1"
	}
	cfg.Seed = strings.TrimSpace(cfg.Seed)
	if cfg.Seed == "" {
		return SplitConfig{}, errors.New("split seed must not be blank")
	}
	if cfg.ValidationStart != nil {
		value := cfg.ValidationStart.UTC()
		cfg.ValidationStart = &value
	}
	if cfg.BlindStart != nil {
		value := cfg.BlindStart.UTC()
		cfg.BlindStart = &value
	}
	return cfg, nil
}

func validateEvaluationRecord(record EvaluationRecord, cfg SplitConfig) error {
	return validateEvaluationRecordMode(record, cfg, false)
}

func validateEvaluationRecordMode(record EvaluationRecord, cfg SplitConfig, requireGoverned bool) error {
	if err := ValidateCase(record.Case); err != nil {
		return err
	}
	if strings.TrimSpace(record.Source) == "" {
		return errors.New("source is required for group-aware splitting")
	}
	if strings.TrimSpace(record.Site) == "" {
		return errors.New("site is required for group-aware splitting")
	}
	if strings.TrimSpace(record.Session) == "" {
		return errors.New("session is required for group-aware splitting")
	}
	if strings.TrimSpace(record.Fingerprint) == "" {
		return errors.New("fingerprint is required for group-aware splitting")
	}
	expectedFingerprint := CaseFingerprint(record.Case)
	if !strings.EqualFold(strings.TrimSpace(record.Fingerprint), expectedFingerprint) {
		return fmt.Errorf("fingerprint %q does not match case fingerprint %q", record.Fingerprint, expectedFingerprint)
	}
	if record.GovernanceLine < 0 {
		return errors.New("governance_line must not be negative")
	}
	if requireGoverned {
		if strings.TrimSpace(record.GovernancePath) == "" {
			return errors.New("governance_path is required for governed evaluation input")
		}
		if record.GovernanceLine < 1 {
			return errors.New("governance_line must be positive for governed evaluation input")
		}
		if !isLowerHexSHA256(record.RawHash) {
			return errors.New("raw_hash must be a 64-character hexadecimal SHA-256 for governed evaluation input")
		}
		switch strings.ToLower(strings.TrimSpace(record.Decision)) {
		case "auto":
			if strings.TrimSpace(record.ReviewRuleVersion) != "" || strings.TrimSpace(record.Reviewer) != "" || strings.TrimSpace(record.ReviewedAt) != "" {
				return errors.New("auto governed evaluation input must not carry review metadata")
			}
		case "approve":
			if strings.TrimSpace(record.ReviewRuleVersion) == "" {
				return errors.New("review_rule_version is required for approved evaluation input")
			}
			if strings.TrimSpace(record.Reviewer) == "" {
				return errors.New("reviewer is required for approved evaluation input")
			}
			if strings.TrimSpace(record.ReviewedAt) == "" {
				return errors.New("reviewed_at is required for approved evaluation input")
			}
			if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.ReviewedAt)); err != nil {
				return fmt.Errorf("reviewed_at must be RFC3339 for approved evaluation input: %w", err)
			}
		default:
			return errors.New("decision must be auto or approve for governed evaluation input")
		}
	}
	if (cfg.ValidationStart != nil || cfg.BlindStart != nil) && record.Timestamp.IsZero() {
		return errors.New("timestamp is required when time boundaries are configured")
	}
	return nil
}

func isLowerHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func evaluationGroupKeys(record EvaluationRecord) []string {
	return []string{
		"source\x00" + strings.ToLower(strings.TrimSpace(record.Source)),
		"site\x00" + strings.ToLower(strings.TrimSpace(record.Site)),
		"session\x00" + strings.TrimSpace(record.Session),
		"fingerprint\x00" + strings.ToLower(strings.TrimSpace(record.Fingerprint)),
	}
}

// evaluationComponentID hashes every unique grouping key in a connected
// component. Hashing only the first row would make the identifier depend on
// input ordering and could make two distinct components look interchangeable
// in audit logs.
func evaluationComponentID(records []EvaluationRecord, indices []int) string {
	keys := make(map[string]struct{}, len(indices)*4)
	for _, index := range indices {
		if index < 0 || index >= len(records) {
			continue
		}
		for _, key := range evaluationGroupKeys(records[index]) {
			keys[key] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	h := sha256.New()
	for _, key := range ordered {
		_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(key))))
		_, _ = h.Write([]byte(key))
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

func evaluationGroupHash(seed, groupID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	_, _ = h.Write([]byte("\x00"))
	_, _ = h.Write([]byte(groupID))
	return h.Sum64()
}

func splitForGroup(records []EvaluationRecord, indices []int, cfg SplitConfig, groupID string) (EvaluationSplit, error) {
	if cfg.ValidationStart != nil || cfg.BlindStart != nil {
		var selected EvaluationSplit
		for _, index := range indices {
			split := splitForTime(records[index].Timestamp, cfg)
			if selected == "" {
				selected = split
			} else if selected != split {
				return "", errors.New("one source/site/session group crosses a time boundary")
			}
		}
		return selected, nil
	}

	hash := evaluationGroupHash(cfg.Seed, groupID)
	// Use a unit interval without floating-point overflow or modulo bias large
	// enough to affect a split boundary.
	bucket := float64(hash) / float64(^uint64(0))
	if bucket >= 1-cfg.BlindFraction {
		return SplitBlind, nil
	}
	if bucket >= 1-cfg.BlindFraction-cfg.ValidationFraction {
		return SplitValidation, nil
	}
	return SplitTrain, nil
}

func splitForTime(timestamp time.Time, cfg SplitConfig) EvaluationSplit {
	if cfg.BlindStart != nil && !timestamp.Before(*cfg.BlindStart) {
		return SplitBlind
	}
	if cfg.ValidationStart != nil && !timestamp.Before(*cfg.ValidationStart) {
		return SplitValidation
	}
	return SplitTrain
}

// ValidateEvaluationSplit rejects any source/site/session/fingerprint key that
// appears in more than one split. It is intentionally independent from the
// splitter so a caller can validate a deserialized assignment artifact too.
func ValidateEvaluationSplit(records []AssignedEvaluationRecord) error {
	if len(records) == 0 {
		return errors.New("assigned evaluation set is empty")
	}
	type keyAssignment struct {
		split EvaluationSplit
		group string
	}
	keys := make(map[string]keyAssignment, len(records)*4)
	groups := make(map[string]string, len(records))
	fingerprints := make(map[string]int, len(records))
	for i, record := range records {
		if record.Split != SplitTrain && record.Split != SplitValidation && record.Split != SplitBlind {
			return fmt.Errorf("record %d has invalid split %q", i, record.Split)
		}
		if strings.TrimSpace(record.Group) == "" {
			return fmt.Errorf("record %d has empty group id", i)
		}
		if err := validateEvaluationRecord(record.EvaluationRecord, SplitConfig{}); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		fingerprint := strings.ToLower(strings.TrimSpace(record.Fingerprint))
		if previous, ok := fingerprints[fingerprint]; ok {
			return fmt.Errorf("records %d and %d duplicate fingerprint %s", previous, i, record.Fingerprint)
		}
		fingerprints[fingerprint] = i
		if previous, ok := groups[record.Group]; ok && previous != string(record.Split) {
			return fmt.Errorf("group %q appears in both %s and %s", record.Group, previous, record.Split)
		}
		groups[record.Group] = string(record.Split)
		for _, key := range evaluationGroupKeys(record.EvaluationRecord) {
			if previous, ok := keys[key]; ok {
				if previous.split != record.Split {
					return fmt.Errorf("group key appears in both %s and %s", previous.split, record.Split)
				}
				if previous.group != record.Group {
					return fmt.Errorf("group key is assigned to groups %q and %q", previous.group, record.Group)
				}
				continue
			}
			keys[key] = keyAssignment{split: record.Split, group: record.Group}
		}
	}
	return nil
}

// ValidateEvaluationSplitArtifact verifies a split's structural and
// deterministic contract. It permits a governed in-memory staging artifact
// returned by BuildEvaluationSplit to temporarily lack a governance binding so
// the caller can attach the independently verified manifest identity. JSON
// decoding and LoadEvaluationSplitArtifact use the strict mode below and fail
// closed if a serialized governed artifact lacks that binding.
func ValidateEvaluationSplitArtifact(artifact EvaluationSplitArtifact) error {
	return validateEvaluationSplitArtifact(artifact, false)
}

func validateEvaluationSplitArtifact(artifact EvaluationSplitArtifact, requireGovernanceBinding bool) error {
	if artifact.Version != EvaluationSplitArtifactVersion {
		return fmt.Errorf("unsupported evaluation split version %q", artifact.Version)
	}
	policy := strings.TrimSpace(artifact.AssignmentPolicy)
	if policy == "" {
		// Artifacts emitted before assignment_policy was introduced are treated as
		// the original hash-only v1 contract. This avoids silently changing their
		// membership while still requiring new artifacts to declare their policy.
		policy = legacyEvaluationSplitAssignmentPolicy
	}
	if policy != EvaluationSplitAssignmentPolicy && policy != legacyEvaluationSplitAssignmentPolicy {
		return fmt.Errorf("unsupported evaluation split assignment policy %q", artifact.AssignmentPolicy)
	}
	if artifact.InputRecords != len(artifact.Records) {
		return fmt.Errorf("input_records=%d does not match records=%d", artifact.InputRecords, len(artifact.Records))
	}
	if artifact.InputRecords < 1 {
		return errors.New("evaluation split artifact has no records")
	}
	if artifact.RecordsSHA256 == "" {
		if artifact.Governed {
			return errors.New("governed evaluation split artifact requires records_sha256")
		}
	} else {
		if !isLowerHexSHA256(artifact.RecordsSHA256) {
			return errors.New("evaluation split artifact records_sha256 must be a 64-character lowercase SHA-256")
		}
		recomputed, err := EvaluationSplitRecordsSHA256(artifact.Records)
		if err != nil {
			return fmt.Errorf("hash evaluation split artifact records: %w", err)
		}
		if recomputed != artifact.RecordsSHA256 {
			return fmt.Errorf("evaluation split artifact records_sha256 mismatch: got %s want %s", artifact.RecordsSHA256, recomputed)
		}
	}
	// Keep this check after records_sha256 verification: a tampered record list
	// must report the stale digest even if the attacker also removed the binding.
	if requireGovernanceBinding && artifact.Governed && artifact.Governance == nil {
		return errors.New("serialized governed evaluation split artifact requires a governance binding")
	}
	if artifact.Governance != nil {
		if err := ValidateEvaluationGovernanceBinding(artifact.Governance); err != nil {
			return fmt.Errorf("invalid governance binding: %w", err)
		}
		if !artifact.Governed {
			return errors.New("governance binding requires a governed artifact")
		}
		if artifact.Governance.FormalRecords != artifact.InputRecords {
			return fmt.Errorf("governance binding formal_records=%d does not match input_records=%d", artifact.Governance.FormalRecords, artifact.InputRecords)
		}
	}
	if artifact.Governed {
		for i, record := range artifact.Records {
			if err := validateEvaluationRecordMode(record.EvaluationRecord, artifact.Config, true); err != nil {
				return fmt.Errorf("governed artifact record %d: %w", i, err)
			}
		}
	}
	if err := validateSplitSummary(artifact.Records, artifact.Summary); err != nil {
		return err
	}
	if err := ValidateEvaluationSplit(artifact.Records); err != nil {
		return err
	}
	normalized, err := normalizeSplitConfig(artifact.Config)
	if err != nil {
		return fmt.Errorf("invalid artifact config: %w", err)
	}
	if !sameSplitConfig(normalized, artifact.Config) {
		return errors.New("artifact config is not normalized")
	}
	expected, expectedSummary, err := groupAwareSplit(evaluationRecords(artifact.Records), normalized, policy == EvaluationSplitAssignmentPolicy)
	if err != nil {
		return fmt.Errorf("recompute split: %w", err)
	}
	if expectedSummary != artifact.Summary {
		return fmt.Errorf("artifact summary does not match deterministic assignment: got %+v want %+v", artifact.Summary, expectedSummary)
	}
	for i := range artifact.Records {
		if expected[i].Split != artifact.Records[i].Split || expected[i].Group != artifact.Records[i].Group {
			return fmt.Errorf("record %d assignment does not match artifact config", i)
		}
	}
	stats := artifact.LoadStats
	if stats.TotalRecords != artifact.InputRecords {
		return fmt.Errorf("load_stats.total_records=%d does not match input_records=%d", stats.TotalRecords, artifact.InputRecords)
	}
	if stats.SelectedRecords != artifact.InputRecords {
		return fmt.Errorf("load_stats.selected_records=%d does not match complete input", stats.SelectedRecords)
	}
	if stats.NonEmptyLines < stats.TotalRecords || stats.SkippedOverlong != 0 || stats.TotalRecords < 0 || stats.SelectedRecords < 0 || stats.NonEmptyLines < 0 || stats.SkippedOverlong < 0 {
		return fmt.Errorf("invalid load_stats: %+v", stats)
	}
	return nil
}

func evaluationRecords(records []AssignedEvaluationRecord) []EvaluationRecord {
	out := make([]EvaluationRecord, len(records))
	for i := range records {
		out[i] = records[i].EvaluationRecord
	}
	return out
}

func validateSplitSummary(records []AssignedEvaluationRecord, summary SplitSummary) error {
	var got SplitSummary
	groups := make(map[string]struct{}, len(records))
	for _, record := range records {
		switch record.Split {
		case SplitTrain:
			got.Train++
		case SplitValidation:
			got.Validation++
		case SplitBlind:
			got.Blind++
		default:
			return fmt.Errorf("invalid split %q in summary validation", record.Split)
		}
		groups[record.Group] = struct{}{}
	}
	got.Groups = len(groups)
	// Repaired is an assignment-policy diagnostic and cannot be inferred from
	// record counts alone. The deterministic recomputation in
	// ValidateEvaluationSplitArtifact verifies it after the policy is known.
	if got.Train != summary.Train || got.Validation != summary.Validation ||
		got.Blind != summary.Blind || got.Groups != summary.Groups {
		return fmt.Errorf("split summary mismatch: got %+v want %+v", summary, got)
	}
	return nil
}

func sameSplitConfig(a, b SplitConfig) bool {
	if a.Seed != b.Seed || a.ValidationFraction != b.ValidationFraction || a.BlindFraction != b.BlindFraction {
		return false
	}
	return sameTimePointer(a.ValidationStart, b.ValidationStart) && sameTimePointer(a.BlindStart, b.BlindStart)
}

func sameTimePointer(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// WilsonInterval99 returns a two-sided Wilson score interval at 99% coverage.
// The lower and upper values are fractions in [0,1]. It is suitable for the
// one-sided policy checks used by the evaluation gate: FPR uses upper, while
// TPR uses lower. Invalid or empty denominators return ok=false.
func WilsonInterval99(successes, total int) (lower, upper float64, ok bool) {
	if total <= 0 || successes < 0 || successes > total {
		return 0, 0, false
	}
	const z = 2.3263478740408408
	n := float64(total)
	p := float64(successes) / n
	z2 := z * z
	denom := 1 + z2/n
	center := p + z2/(2*n)
	half := z * math.Sqrt(p*(1-p)/n+z2/(4*n*n))
	lower = clamp01((center - half) / denom)
	upper = clamp01((center + half) / denom)
	// Avoid cancellation noise at the two exact endpoints. Besides making the
	// report easier to read, this preserves the mathematically expected [0, x]
	// and [x, 1] one-sided bounds for all-failure/all-success samples.
	if successes == 0 {
		lower = 0
	}
	if successes == total {
		upper = 1
	}
	return lower, upper, true
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

type unionFind struct {
	parent []int
	rank   []uint8
}

func newUnionFind(size int) *unionFind {
	parent := make([]int, size)
	for i := range parent {
		parent[i] = i
	}
	return &unionFind{parent: parent, rank: make([]uint8, size)}
}

func (u *unionFind) find(value int) int {
	if u.parent[value] != value {
		u.parent[value] = u.find(u.parent[value])
	}
	return u.parent[value]
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if u.rank[ra] < u.rank[rb] {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
	if u.rank[ra] == u.rank[rb] {
		u.rank[ra]++
	}
}
