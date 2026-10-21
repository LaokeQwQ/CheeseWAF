// Package intelstore persists vulnerability intelligence, compiled rule
// candidates, and import jobs. It is a narrow, context-aware data layer with no
// rule activation: candidates are stored exactly as the review pipeline built
// them. Both SQLite and PostgreSQL implementations share these contracts.
package intelstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

// Errors returned by every Store implementation. Callers map ErrNotFound to
// HTTP 404 and ErrConflict to HTTP 409.
var (
	ErrInvalid  = errors.New("intelstore: invalid input")
	ErrNotFound = errors.New("intelstore: not found")
	ErrConflict = errors.New("intelstore: conflict")
)

const (
	// DefaultListLimit is used when a caller does not request a page size.
	DefaultListLimit = 50
	// MaxListLimit is the hard cap on any list query.
	MaxListLimit = 200

	maxIDBytes            = 128
	maxTitleBytes         = 512
	maxContentHashBytes   = 128
	maxExcerptBytes       = 16 << 10
	maxListJSONBytes      = 64 << 10
	maxRuleJSONBytes      = intel.MaxRuleJSONBytes
	maxProvenanceBytes    = 64 << 10
	maxExtractionJSONSize = 64 << 10
	maxJobErrorBytes      = 1024
	maxURLBytes           = 2048
	maxApproverBytes      = 128
	maxJobStatusBytes     = 32
)

var safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)

// Import job status values. A job is written as pending before the fetch starts
// and is updated once the import either completes or fails.
const (
	ImportStatusPending   = "pending"
	ImportStatusCompleted = "completed"
	ImportStatusFailed    = "failed"
)

// ItemFilter selects items for ListItems. State filters on the review state of
// any candidate compiled from the item, because items themselves are immutable.
type ItemFilter struct {
	Limit int
	State intel.CandidateState
}

// CandidateFilter selects candidates for ListCandidates. Empty fields are
// wildcards.
type CandidateFilter struct {
	Limit  int
	SiteID string
	State  intel.CandidateState
}

// CandidateUpdate is an atomic candidate mutation. Nil fields are left
// untouched. ApprovedBy records human approval and requires the resulting
// candidate to remain valid under intel.ValidateCandidate.
type CandidateUpdate struct {
	State      *intel.CandidateState
	Action     *string
	ApprovedBy string
	ExpiresAt  *time.Time
}

// ImportJob records one URL import attempt. URL is stored without query or
// fragment so signed URLs and tokens are never persisted.
type ImportJob struct {
	ID             string    `json:"id"`
	URL            string    `json:"url"`
	ContentHash    string    `json:"content_hash,omitempty"`
	Status         string    `json:"status"`
	ExtractionJSON string    `json:"extraction_json,omitempty"`
	Error          string    `json:"error,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Store is the persistence contract for the intel pipeline.
type Store interface {
	UpsertSource(ctx context.Context, source intel.Source) error
	ListSources(ctx context.Context) ([]intel.Source, error)
	GetSource(ctx context.Context, id string) (intel.Source, error)

	// InsertItem deduplicates on (source_id, content_hash). It returns the
	// stored item and whether it was newly created.
	InsertItem(ctx context.Context, item intel.Item) (intel.Item, bool, error)
	ListItems(ctx context.Context, filter ItemFilter) ([]intel.Item, error)
	GetItem(ctx context.Context, id string) (intel.Item, error)

	// InsertCandidate returns the stored candidate and whether it was newly
	// created. Re-inserting the deterministic ID is idempotent.
	InsertCandidate(ctx context.Context, candidate intel.Candidate) (intel.Candidate, bool, error)
	ListCandidates(ctx context.Context, filter CandidateFilter) ([]intel.Candidate, error)
	GetCandidate(ctx context.Context, id string) (intel.Candidate, error)
	UpdateCandidate(ctx context.Context, id string, update CandidateUpdate) (intel.Candidate, error)
	UpdateCandidateState(ctx context.Context, id string, state intel.CandidateState, approvedBy string) (intel.Candidate, error)
	UpdateCandidateAction(ctx context.Context, id string, action, approvedBy string) (intel.Candidate, error)
	UpdateCandidateExpiry(ctx context.Context, id string, expiresAt time.Time) (intel.Candidate, error)
	// ExpireCandidates marks every unreviewed, past-due candidate as expired and
	// reports how many rows changed.
	ExpireCandidates(ctx context.Context, now time.Time) (int64, error)

	InsertImportJob(ctx context.Context, job ImportJob) error
	UpdateImportJob(ctx context.Context, job ImportJob) error
	GetImportJob(ctx context.Context, id string) (ImportJob, error)
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return DefaultListLimit
	}
	if limit > MaxListLimit {
		return MaxListLimit
	}
	return limit
}

func normalizeSource(source intel.Source) (intel.Source, error) {
	source.ID = strings.TrimSpace(source.ID)
	source.Type = strings.ToLower(strings.TrimSpace(source.Type))
	source.URL = strings.TrimSpace(source.URL)
	source.Trust = intel.ParseTrustLevel(string(source.Trust))
	if err := intel.ValidateSource(source); err != nil {
		return intel.Source{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return source, nil
}

func normalizeItem(item intel.Item) (intel.Item, error) {
	item.SourceID = strings.TrimSpace(item.SourceID)
	item.Title = strings.TrimSpace(item.Title)
	item.ContentHash = strings.ToLower(strings.TrimSpace(item.ContentHash))
	item.AttackVector = strings.TrimSpace(item.AttackVector)
	item.ExploitStatus = strings.TrimSpace(item.ExploitStatus)
	if !safeIDPattern.MatchString(item.SourceID) {
		return intel.Item{}, fmt.Errorf("%w: item source id must match %s", ErrInvalid, safeIDPattern)
	}
	if item.ContentHash == "" {
		item.ContentHash = computeItemHash(item)
	}
	if len(item.ContentHash) > maxContentHashBytes {
		return intel.Item{}, fmt.Errorf("%w: item content hash exceeds %d bytes", ErrInvalid, maxContentHashBytes)
	}
	if len(item.Title) > maxTitleBytes {
		return intel.Item{}, fmt.Errorf("%w: item title exceeds %d bytes", ErrInvalid, maxTitleBytes)
	}
	if err := checkText("item title", item.Title, maxTitleBytes, true); err != nil {
		return intel.Item{}, err
	}
	if err := checkText("item attack vector", item.AttackVector, maxIDBytes, true); err != nil {
		return intel.Item{}, err
	}
	if err := checkText("item exploit status", item.ExploitStatus, maxIDBytes, true); err != nil {
		return intel.Item{}, err
	}
	if err := checkText("item raw excerpt", item.RawExcerpt, maxExcerptBytes, true); err != nil {
		return intel.Item{}, err
	}
	if err := checkList("external ids", item.ExternalIDs, 64, 256); err != nil {
		return intel.Item{}, err
	}
	if err := checkList("products", item.Products, 64, 256); err != nil {
		return intel.Item{}, err
	}
	if err := checkList("affected versions", item.AffectedVersions, 64, 256); err != nil {
		return intel.Item{}, err
	}
	if err := checkList("corroborating source ids", item.CorroboratingSourceIDs, 32, maxIDBytes); err != nil {
		return intel.Item{}, err
	}
	if len(item.References) > 32 {
		return intel.Item{}, fmt.Errorf("%w: too many item references", ErrInvalid)
	}
	for _, reference := range item.References {
		if err := intel.ValidateReferenceURL(reference); err != nil {
			return intel.Item{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	if _, err := json.Marshal(item.ExternalIDs); err != nil {
		return intel.Item{}, fmt.Errorf("%w: encode external ids: %v", ErrInvalid, err)
	}
	if id := strings.TrimSpace(item.ID); id != "" {
		if !safeIDPattern.MatchString(id) {
			return intel.Item{}, fmt.Errorf("%w: item id must match %s", ErrInvalid, safeIDPattern)
		}
		item.ID = id
	} else {
		sum := sha256.Sum256([]byte(item.SourceID + "\n" + item.ContentHash))
		item.ID = "item-" + hex.EncodeToString(sum[:])[:16]
	}
	return item, nil
}

func computeItemHash(item intel.Item) string {
	hasher := sha256.New()
	for _, part := range []string{item.SourceID, item.Title, item.AttackVector, item.ExploitStatus, item.RawExcerpt} {
		_, _ = hasher.Write([]byte(part))
		_, _ = hasher.Write([]byte{'\n'})
	}
	for _, group := range [][]string{item.ExternalIDs, item.Products, item.AffectedVersions, item.References} {
		for _, value := range group {
			_, _ = hasher.Write([]byte(value))
			_, _ = hasher.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func normalizeCandidate(candidate intel.Candidate) (intel.Candidate, error) {
	candidate.ID = strings.TrimSpace(candidate.ID)
	candidate.ItemID = strings.TrimSpace(candidate.ItemID)
	candidate.SiteID = strings.TrimSpace(candidate.SiteID)
	candidate.Action = strings.ToLower(strings.TrimSpace(candidate.Action))
	candidate.State = intel.CandidateState(strings.ToLower(strings.TrimSpace(string(candidate.State))))
	if candidate.CreatedAt.IsZero() {
		candidate.CreatedAt = time.Now().UTC()
	}
	if candidate.TTL <= 0 {
		candidate.TTL = intel.DefaultCandidateTTL
	}
	if candidate.Provenance.SourceID == "" {
		candidate.Provenance.SourceID = "unknown"
	}
	if len(candidate.RuleJSON) > maxRuleJSONBytes {
		return intel.Candidate{}, fmt.Errorf("%w: candidate rule_json exceeds %d bytes", ErrInvalid, maxRuleJSONBytes)
	}
	if err := intel.ValidateCandidate(candidate); err != nil {
		return intel.Candidate{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return candidate, nil
}

func normalizeJob(job ImportJob) (ImportJob, error) {
	job.ID = strings.TrimSpace(job.ID)
	job.URL = strings.TrimSpace(job.URL)
	job.Status = strings.ToLower(strings.TrimSpace(job.Status))
	job.ContentHash = strings.ToLower(strings.TrimSpace(job.ContentHash))
	job.Error = strings.TrimSpace(job.Error)
	if !safeIDPattern.MatchString(job.ID) {
		return ImportJob{}, fmt.Errorf("%w: import job id must match %s", ErrInvalid, safeIDPattern)
	}
	if job.URL == "" || len(job.URL) > maxURLBytes {
		return ImportJob{}, fmt.Errorf("%w: import job url is required and must not exceed %d bytes", ErrInvalid, maxURLBytes)
	}
	if err := checkText("import job url", job.URL, maxURLBytes, false); err != nil {
		return ImportJob{}, err
	}
	switch job.Status {
	case ImportStatusPending, ImportStatusCompleted, ImportStatusFailed:
	default:
		return ImportJob{}, fmt.Errorf("%w: import job status must be pending, completed, or failed", ErrInvalid)
	}
	if len(job.Status) > maxJobStatusBytes {
		return ImportJob{}, fmt.Errorf("%w: import job status is too long", ErrInvalid)
	}
	if len(job.ContentHash) > maxContentHashBytes {
		return ImportJob{}, fmt.Errorf("%w: import job content hash is too long", ErrInvalid)
	}
	if job.ExtractionJSON == "" {
		job.ExtractionJSON = "{}"
	}
	if len(job.ExtractionJSON) > maxExtractionJSONSize {
		return ImportJob{}, fmt.Errorf("%w: import job extraction exceeds %d bytes", ErrInvalid, maxExtractionJSONSize)
	}
	if !json.Valid([]byte(job.ExtractionJSON)) {
		return ImportJob{}, fmt.Errorf("%w: import job extraction is not valid JSON", ErrInvalid)
	}
	if len(job.Error) > maxJobErrorBytes {
		return ImportJob{}, fmt.Errorf("%w: import job error exceeds %d bytes", ErrInvalid, maxJobErrorBytes)
	}
	if err := checkText("import job error", job.Error, maxJobErrorBytes, true); err != nil {
		return ImportJob{}, err
	}
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	} else {
		job.CreatedAt = job.CreatedAt.UTC()
	}
	if job.UpdatedAt.IsZero() {
		job.UpdatedAt = job.CreatedAt
	} else {
		job.UpdatedAt = job.UpdatedAt.UTC()
	}
	return job, nil
}

func validateStateFilter(state intel.CandidateState) error {
	if state == "" {
		return nil
	}
	if !state.Valid() {
		return fmt.Errorf("%w: invalid candidate state %q", ErrInvalid, state)
	}
	return nil
}

func checkText(label, value string, max int, allowEmpty bool) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%w: %s is required", ErrInvalid, label)
	}
	if len(value) > max {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, max)
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalid, label)
		}
	}
	return nil
}

func checkList(label string, values []string, maxItems, maxItemBytes int) error {
	if len(values) > maxItems {
		return fmt.Errorf("%w: %s exceeds %d entries", ErrInvalid, label, maxItems)
	}
	total := 0
	for _, value := range values {
		if err := checkText(label+" entry", value, maxItemBytes, false); err != nil {
			return err
		}
		total += len(value)
	}
	if total > maxListJSONBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, maxListJSONBytes)
	}
	return nil
}

// SanitizeURL removes credentials, query parameters, and fragments before a URL
// is persisted or surfaced. Invalid URLs yield an empty string.
func SanitizeURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

// NewImportJob builds a pending job with a caller-supplied identifier.
func NewImportJob(id, rawURL string, now time.Time) ImportJob {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return ImportJob{
		ID:             id,
		URL:            SanitizeURL(rawURL),
		Status:         ImportStatusPending,
		ExtractionJSON: "{}",
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
}
