// Package impact estimates the blast radius of an intelligence rule candidate
// and gates its deterministic rollout. It performs no I/O and has no side
// effects: callers persist plans and apply returned transitions.
package impact

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Errors returned by estimation and rollout gates. Callers can use errors.Is to
// distinguish a policy rejection from a programming error.
var (
	ErrInvalidPolicy        = errors.New("impact: invalid policy")
	ErrInvalidCandidate     = errors.New("impact: invalid candidate")
	ErrInvalidProfile       = errors.New("impact: invalid profile")
	ErrInvalidPlan          = errors.New("impact: invalid plan")
	ErrInvalidTransition    = errors.New("impact: invalid plan transition")
	ErrPlanExpired          = errors.New("impact: plan expired")
	ErrShadowTooShort       = errors.New("impact: shadow observation period is too short")
	ErrInsufficientSamples  = errors.New("impact: insufficient observations")
	ErrInvalidCanaryPercent = errors.New("impact: canary percentage is out of bounds")
	ErrApprovalRequired     = errors.New("impact: human approval is required")
	ErrHealthThreshold      = errors.New("impact: health threshold exceeded")
)

var safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)

// Bounds for candidate-provided values. Profiles are generated locally from
// aggregate counters, so the limits stay small and deterministic.
const (
	maxIDBytes        = 128
	maxPathBytes      = 512
	maxMethods        = 8
	maxStatusCodes    = 64
	maxShapesPerPath  = 32
	maxCandidatesSeen = 256
)

// Verdict is the deterministic recommendation for a candidate under a policy.
type Verdict string

const (
	// VerdictAllowShadow permits a non-blocking shadow deployment.
	VerdictAllowShadow Verdict = "allow-shadow"
	// VerdictNeedsReview requires a human decision before any rollout.
	VerdictNeedsReview Verdict = "needs-review"
	// VerdictReject blocks the candidate from rollout.
	VerdictReject Verdict = "reject"
)

// Valid reports whether the verdict is one of the supported values.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictAllowShadow, VerdictNeedsReview, VerdictReject:
		return true
	default:
		return false
	}
}

// Policy holds rollout thresholds. Zero values are replaced by the secure
// defaults in DefaultPolicy. Blocking actions always require human approval
// unless AllowUnapprovedBlock is explicitly set.
type Policy struct {
	// MaxBenignBlockRate is the largest tolerated share of benign requests that
	// the candidate would block. Default 0.001 (0.1%).
	MaxBenignBlockRate float64
	// MinObservations is the smallest number of in-scope requests needed for a
	// trustworthy estimate and for shadow/canary promotion. Default 1000.
	MinObservations int64
	// MaxBroadness is the largest tolerated match rate over in-scope traffic.
	// Default 0.05 (5%).
	MaxBroadness float64
	// AllowUnapprovedBlock removes the human approval gate for block actions.
	AllowUnapprovedBlock bool
	// MinShadowDuration is the minimum time a plan must stay in shadow before
	// canary promotion. Default 1h.
	MinShadowDuration time.Duration
	// CanaryMinPercent and CanaryMaxPercent bound canary traffic in percent
	// points (0-100). Defaults 1 and 25.
	CanaryMinPercent float64
	CanaryMaxPercent float64
	// MaxErrorRate is the canary/active error rate that triggers rollback.
	// Default 0.02 (2%).
	MaxErrorRate float64
	// MaxFalsePositiveRate is the canary/active false-positive rate that
	// triggers rollback. Default 0.001 (0.1%).
	MaxFalsePositiveRate float64
	// MaxTTL bounds plan lifetime. Default 90 days.
	MaxTTL time.Duration
}

// DefaultPolicy returns the secure rollout defaults.
func DefaultPolicy() Policy {
	return Policy{
		MaxBenignBlockRate:   0.001,
		MinObservations:      1000,
		MaxBroadness:         0.05,
		AllowUnapprovedBlock: false,
		MinShadowDuration:    time.Hour,
		CanaryMinPercent:     1,
		CanaryMaxPercent:     25,
		MaxErrorRate:         0.02,
		MaxFalsePositiveRate: 0.001,
		MaxTTL:               90 * 24 * time.Hour,
	}
}

// effective fills zero fields with defaults while leaving explicit values
// untouched. Negative values remain and fail validation.
func (p Policy) effective() Policy {
	d := DefaultPolicy()
	if p.MaxBenignBlockRate == 0 {
		p.MaxBenignBlockRate = d.MaxBenignBlockRate
	}
	if p.MinObservations == 0 {
		p.MinObservations = d.MinObservations
	}
	if p.MaxBroadness == 0 {
		p.MaxBroadness = d.MaxBroadness
	}
	if p.MinShadowDuration == 0 {
		p.MinShadowDuration = d.MinShadowDuration
	}
	if p.CanaryMinPercent == 0 {
		p.CanaryMinPercent = d.CanaryMinPercent
	}
	if p.CanaryMaxPercent == 0 {
		p.CanaryMaxPercent = d.CanaryMaxPercent
	}
	if p.MaxErrorRate == 0 {
		p.MaxErrorRate = d.MaxErrorRate
	}
	if p.MaxFalsePositiveRate == 0 {
		p.MaxFalsePositiveRate = d.MaxFalsePositiveRate
	}
	if p.MaxTTL == 0 {
		p.MaxTTL = d.MaxTTL
	}
	return p
}

// Validate checks that every threshold is in a safe range.
func (p Policy) Validate() error {
	e := p.effective()
	switch {
	case !(e.MaxBenignBlockRate > 0 && e.MaxBenignBlockRate <= 1):
		return fmt.Errorf("%w: max benign block rate must be within (0, 1]", ErrInvalidPolicy)
	case e.MinObservations <= 0:
		return fmt.Errorf("%w: min observations must be positive", ErrInvalidPolicy)
	case !(e.MaxBroadness > 0 && e.MaxBroadness <= 1):
		return fmt.Errorf("%w: max broadness must be within (0, 1]", ErrInvalidPolicy)
	case e.MinShadowDuration <= 0:
		return fmt.Errorf("%w: min shadow duration must be positive", ErrInvalidPolicy)
	case !(e.CanaryMinPercent > 0 && e.CanaryMinPercent <= 100):
		return fmt.Errorf("%w: canary min percent must be within (0, 100]", ErrInvalidPolicy)
	case !(e.CanaryMaxPercent > 0 && e.CanaryMaxPercent <= 100):
		return fmt.Errorf("%w: canary max percent must be within (0, 100]", ErrInvalidPolicy)
	case e.CanaryMinPercent > e.CanaryMaxPercent:
		return fmt.Errorf("%w: canary min percent exceeds canary max percent", ErrInvalidPolicy)
	case !(e.MaxErrorRate > 0 && e.MaxErrorRate <= 1):
		return fmt.Errorf("%w: max error rate must be within (0, 1]", ErrInvalidPolicy)
	case !(e.MaxFalsePositiveRate > 0 && e.MaxFalsePositiveRate <= 1):
		return fmt.Errorf("%w: max false positive rate must be within (0, 1]", ErrInvalidPolicy)
	case e.MaxTTL <= 0:
		return fmt.Errorf("%w: max TTL must be positive", ErrInvalidPolicy)
	}
	return nil
}

// StatusCounts is the response status distribution for one profile.
type StatusCounts map[int]int64

// ShapeCounts counts multipart request shapes for one profile.
type ShapeCounts map[string]int64

// MatchObservation reports how often one candidate matched a profile and how
// many of those matches were observed on successful (benign) responses.
type MatchObservation struct {
	Count  int64
	Benign int64
}

// MatchCounts maps candidate ID to its observation in one profile.
type MatchCounts map[string]MatchObservation

// Profile is an aggregate of observed traffic for one site/path/method. Callers
// must not provide raw request bodies or identifiers.
type Profile struct {
	SiteID          string       `json:"site_id"`
	Path            string       `json:"path"`
	Method          string       `json:"method"`
	Requests        int64        `json:"requests"`
	Statuses        StatusCounts `json:"statuses,omitempty"`
	MultipartShapes ShapeCounts  `json:"multipart_shapes,omitempty"`
	Matches         MatchCounts  `json:"matches,omitempty"`
}

// Candidate is the minimal rule view needed to estimate impact. It mirrors the
// scope and action of an intel candidate without importing persistence types.
type Candidate struct {
	ID         string   `json:"id"`
	SiteID     string   `json:"site_id"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	Action     string   `json:"action"`
	Approved   bool     `json:"approved,omitempty"`
}

// Assessment is the deterministic impact report for one candidate.
type Assessment struct {
	CandidateID              string        `json:"candidate_id"`
	Observations             int64         `json:"observations"`
	WouldBlock               int64         `json:"would_block"`
	UniquePaths              []string      `json:"unique_paths"`
	PathCoverage             float64       `json:"path_coverage"`
	BenignBlocks             int64         `json:"benign_blocks"`
	BenignBlockRate          float64       `json:"benign_block_rate"`
	MatchRate                float64       `json:"match_rate"`
	Broadness                float64       `json:"broadness"`
	MultipartShapes          int           `json:"multipart_shapes"`
	StatusDistribution       map[int]int64 `json:"status_distribution,omitempty"`
	Verdict                  Verdict       `json:"verdict"`
	RequiresApprovalForBlock bool          `json:"requires_approval_for_block"`
	Reasons                  []string      `json:"reasons,omitempty"`
}

// Estimate applies the default policy to a candidate and its profiles.
func Estimate(candidate Candidate, profiles []Profile) Assessment {
	return DefaultPolicy().Estimate(candidate, profiles)
}

// Estimate applies the policy to a candidate and its profiles. It never mutates
// the candidate or profiles and is independent of input ordering.
func (p Policy) Estimate(candidate Candidate, profiles []Profile) Assessment {
	normalized, candidateErr := normalizeCandidate(candidate)
	result := Assessment{CandidateID: normalized.ID, UniquePaths: []string{}}

	effective := p.effective()
	if err := effective.Validate(); err != nil {
		result.Verdict = VerdictReject
		result.Reasons = []string{err.Error()}
		return result
	}
	if candidateErr != nil {
		result.Verdict = VerdictReject
		result.Reasons = []string{candidateErr.Error()}
		return result
	}

	matched := matchingProfiles(normalized, profiles)
	if len(matched) == 0 {
		result.Verdict = VerdictNeedsReview
		result.Reasons = []string{"no profiles match the candidate scope"}
		result.RequiresApprovalForBlock = requiresApproval(normalized, effective)
		return result
	}
	if err := validateProfiles(matched); err != nil {
		result.Verdict = VerdictReject
		result.Reasons = []string{err.Error()}
		result.RequiresApprovalForBlock = requiresApproval(normalized, effective)
		return result
	}

	matchedPaths := make(map[string]struct{}, len(matched))
	observedPaths := make(map[string]struct{}, len(matched))
	shapes := make(map[string]struct{})
	statuses := make(map[int]int64)
	seenCandidates := make(map[string]struct{})

	for _, profile := range matched {
		observedPaths[profile.Path] = struct{}{}
		observation := profile.Matches[normalized.ID]
		for candidateID := range profile.Matches {
			seenCandidates[candidateID] = struct{}{}
		}
		if len(seenCandidates) > maxCandidatesSeen {
			result.Verdict = VerdictReject
			result.Reasons = []string{fmt.Sprintf("too many candidate match sets in profiles (max %d)", maxCandidatesSeen)}
			result.RequiresApprovalForBlock = requiresApproval(normalized, effective)
			return result
		}
		result.Observations = addInt64(result.Observations, profile.Requests)
		for code, count := range profile.Statuses {
			statuses[code] = addInt64(statuses[code], count)
		}
		if observation.Count <= 0 {
			continue
		}
		matchedPaths[profile.Path] = struct{}{}
		result.WouldBlock = addInt64(result.WouldBlock, observation.Count)
		result.BenignBlocks = addInt64(result.BenignBlocks, observation.Benign)
		for shape, count := range profile.MultipartShapes {
			if count > 0 {
				shapes[shape] = struct{}{}
			}
		}
	}

	result.UniquePaths = sortedKeys(matchedPaths)
	result.PathCoverage = ratio(len(matchedPaths), len(observedPaths))
	result.MultipartShapes = len(shapes)
	if len(statuses) > 0 {
		result.StatusDistribution = statuses
	}
	result.MatchRate = ratioInt(result.WouldBlock, result.Observations)
	result.Broadness = result.MatchRate
	result.BenignBlockRate = ratioInt(result.BenignBlocks, result.Observations)
	result.RequiresApprovalForBlock = requiresApproval(normalized, effective)

	switch {
	case result.Broadness > effective.MaxBroadness:
		result.Verdict = VerdictReject
		result.Reasons = []string{fmt.Sprintf("match rate %s exceeds broadness limit %s", formatPercent(result.Broadness), formatPercent(effective.MaxBroadness))}
	case result.BenignBlockRate > effective.MaxBenignBlockRate:
		result.Verdict = VerdictReject
		result.Reasons = []string{fmt.Sprintf("benign block rate %s exceeds limit %s", formatPercent(result.BenignBlockRate), formatPercent(effective.MaxBenignBlockRate))}
	case result.Observations < effective.MinObservations:
		result.Verdict = VerdictNeedsReview
		result.Reasons = []string{fmt.Sprintf("insufficient observations: %d < %d", result.Observations, effective.MinObservations)}
	case result.WouldBlock == 0:
		result.Verdict = VerdictNeedsReview
		result.Reasons = []string{"candidate matched no observed requests"}
	default:
		result.Verdict = VerdictAllowShadow
		result.Reasons = []string{"within benign-block and broadness limits"}
	}
	return result
}

func requiresApproval(candidate Candidate, policy Policy) bool {
	return candidate.Action == "block" && !candidate.Approved && !policy.AllowUnapprovedBlock
}

func normalizeCandidate(candidate Candidate) (Candidate, error) {
	candidate.ID = strings.TrimSpace(candidate.ID)
	candidate.SiteID = strings.TrimSpace(candidate.SiteID)
	candidate.PathPrefix = strings.TrimSpace(candidate.PathPrefix)
	candidate.Action = strings.ToLower(strings.TrimSpace(candidate.Action))

	if !safeIDPattern.MatchString(candidate.ID) {
		return candidate, fmt.Errorf("%w: candidate id must match %s", ErrInvalidCandidate, safeIDPattern)
	}
	if !safeIDPattern.MatchString(candidate.SiteID) {
		return candidate, fmt.Errorf("%w: site id must match %s", ErrInvalidCandidate, safeIDPattern)
	}
	switch candidate.SiteID {
	case "*", "global", "all":
		return candidate, fmt.Errorf("%w: candidate scope must name a single site", ErrInvalidCandidate)
	}
	if candidate.PathPrefix != "" {
		if len(candidate.PathPrefix) > maxPathBytes {
			return candidate, fmt.Errorf("%w: path prefix exceeds %d bytes", ErrInvalidCandidate, maxPathBytes)
		}
		if !strings.HasPrefix(candidate.PathPrefix, "/") || candidate.PathPrefix == "/" {
			return candidate, fmt.Errorf("%w: path prefix must start with / and be narrower than /", ErrInvalidCandidate)
		}
		if strings.ContainsAny(candidate.PathPrefix, "?# \t\r\n") {
			return candidate, fmt.Errorf("%w: path prefix must not contain a query, fragment, or whitespace", ErrInvalidCandidate)
		}
	}
	switch candidate.Action {
	case "log", "challenge", "block":
	default:
		return candidate, fmt.Errorf("%w: action must be log, challenge, or block", ErrInvalidCandidate)
	}

	if len(candidate.Methods) > maxMethods {
		return candidate, fmt.Errorf("%w: too many methods (max %d)", ErrInvalidCandidate, maxMethods)
	}
	seen := make(map[string]struct{}, len(candidate.Methods))
	methods := make([]string, 0, len(candidate.Methods))
	for _, method := range candidate.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if !supportedMethod(method) {
			return candidate, fmt.Errorf("%w: unsupported method %q", ErrInvalidCandidate, method)
		}
		if _, exists := seen[method]; exists {
			return candidate, fmt.Errorf("%w: duplicate method %q", ErrInvalidCandidate, method)
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	sort.Strings(methods)
	candidate.Methods = methods
	return candidate, nil
}

func matchingProfiles(candidate Candidate, profiles []Profile) []Profile {
	matched := make([]Profile, 0, len(profiles))
	for _, profile := range profiles {
		profile.SiteID = strings.TrimSpace(profile.SiteID)
		if profile.SiteID != candidate.SiteID {
			continue
		}
		if candidate.PathPrefix != "" && !strings.HasPrefix(profile.Path, candidate.PathPrefix) {
			continue
		}
		if len(candidate.Methods) > 0 {
			method := strings.ToUpper(strings.TrimSpace(profile.Method))
			if method != "" && !contains(candidate.Methods, method) {
				continue
			}
		}
		matched = append(matched, profile)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].Path != matched[j].Path {
			return matched[i].Path < matched[j].Path
		}
		return matched[i].Method < matched[j].Method
	})
	return matched
}

func validateProfiles(profiles []Profile) error {
	for _, profile := range profiles {
		if err := validateProfile(profile); err != nil {
			return err
		}
	}
	return nil
}

func validateProfile(profile Profile) error {
	label := fmt.Sprintf("profile %s %s %s", profile.SiteID, profile.Method, profile.Path)
	if !safeIDPattern.MatchString(profile.SiteID) {
		return fmt.Errorf("%w: %s has an invalid site id", ErrInvalidProfile, label)
	}
	if profile.Path == "" || len(profile.Path) > maxPathBytes || !strings.HasPrefix(profile.Path, "/") {
		return fmt.Errorf("%w: %s has an invalid path", ErrInvalidProfile, label)
	}
	if strings.ContainsAny(profile.Path, "?# \t\r\n") {
		return fmt.Errorf("%w: %s path contains a query, fragment, or whitespace", ErrInvalidProfile, label)
	}
	for _, r := range profile.Path {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s path contains a control character", ErrInvalidProfile, label)
		}
	}
	if method := strings.TrimSpace(profile.Method); method != "" && !supportedMethod(strings.ToUpper(method)) {
		return fmt.Errorf("%w: %s has an unsupported method", ErrInvalidProfile, label)
	}
	if profile.Requests < 0 {
		return fmt.Errorf("%w: %s has a negative request count", ErrInvalidProfile, label)
	}
	if len(profile.Statuses) > maxStatusCodes {
		return fmt.Errorf("%w: %s has too many status codes (max %d)", ErrInvalidProfile, label, maxStatusCodes)
	}
	var statusTotal int64
	for code, count := range profile.Statuses {
		if code < 100 || code > 599 {
			return fmt.Errorf("%w: %s has status code %d out of range", ErrInvalidProfile, label, code)
		}
		if count < 0 {
			return fmt.Errorf("%w: %s has a negative status count", ErrInvalidProfile, label)
		}
		statusTotal = addInt64(statusTotal, count)
	}
	if statusTotal > profile.Requests {
		return fmt.Errorf("%w: %s status counts exceed requests", ErrInvalidProfile, label)
	}
	if len(profile.MultipartShapes) > maxShapesPerPath {
		return fmt.Errorf("%w: %s has too many multipart shapes (max %d)", ErrInvalidProfile, label, maxShapesPerPath)
	}
	var shapeTotal int64
	for shape, count := range profile.MultipartShapes {
		if strings.TrimSpace(shape) == "" {
			return fmt.Errorf("%w: %s has an empty multipart shape", ErrInvalidProfile, label)
		}
		if count < 0 {
			return fmt.Errorf("%w: %s has a negative multipart shape count", ErrInvalidProfile, label)
		}
		shapeTotal = addInt64(shapeTotal, count)
	}
	if shapeTotal > profile.Requests {
		return fmt.Errorf("%w: %s multipart shape counts exceed requests", ErrInvalidProfile, label)
	}
	if len(profile.Matches) > maxCandidatesSeen {
		return fmt.Errorf("%w: %s has too many candidate match sets (max %d)", ErrInvalidProfile, label, maxCandidatesSeen)
	}
	for candidateID, observation := range profile.Matches {
		if !safeIDPattern.MatchString(candidateID) {
			return fmt.Errorf("%w: %s has an invalid candidate id %q", ErrInvalidProfile, label, candidateID)
		}
		if observation.Count < 0 || observation.Benign < 0 || observation.Benign > observation.Count {
			return fmt.Errorf("%w: %s has an invalid match observation for %q", ErrInvalidProfile, label, candidateID)
		}
		if observation.Count > profile.Requests {
			return fmt.Errorf("%w: %s match count exceeds requests", ErrInvalidProfile, label)
		}
	}
	return nil
}

func supportedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func ratioInt(numerator, denominator int64) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func addInt64(left, right int64) int64 {
	if right > 0 && left > math.MaxInt64-right {
		return math.MaxInt64
	}
	if right < 0 && left < math.MinInt64-right {
		return math.MinInt64
	}
	return left + right
}

func formatPercent(value float64) string {
	return strconv.FormatFloat(value*100, 'f', 4, 64) + "%"
}
