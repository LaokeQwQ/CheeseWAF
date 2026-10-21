package pipeline

import "errors"

// Errors returned by ingestion and promotion. Callers can use errors.Is to
// distinguish policy rejection from malformed input or transport failures.
var (
	// ErrInvalid reports malformed configuration, sources, or scope.
	ErrInvalid = errors.New("intel/pipeline: invalid input")
	// ErrQuarantined reports an item that the trust policy did not allow.
	ErrQuarantined = errors.New("intel/pipeline: item quarantined by trust policy")
	// ErrNoSafeRule reports an advisory that cannot be expressed as a narrow
	// rule. Vague advisories yield no candidate.
	ErrNoSafeRule = errors.New("intel/pipeline: no safe minimal rule")
	// ErrExtractionFailed reports an extractor failure for one item.
	ErrExtractionFailed = errors.New("intel/pipeline: extraction failed")
	// ErrDuplicate reports a duplicate or replayed feed item.
	ErrDuplicate = errors.New("intel/pipeline: duplicate or replayed item")
	// ErrLimitExceeded reports a bounded ingestion limit being hit.
	ErrLimitExceeded = errors.New("intel/pipeline: ingestion limit exceeded")
	// ErrImpactRejected reports an impact verdict that forbids promotion.
	ErrImpactRejected = errors.New("intel/pipeline: impact assessment rejected the candidate")
	// ErrApprovalRequired reports a promotion that needs a named human approver.
	ErrApprovalRequired = errors.New("intel/pipeline: human approval required")
	// ErrExpired reports a candidate or plan whose TTL has elapsed.
	ErrExpired = errors.New("intel/pipeline: candidate expired")
)
