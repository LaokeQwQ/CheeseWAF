package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// DefaultCandidateTTL is used when a candidate is created without an explicit
// TTL. Every candidate still carries a positive TTL.
const DefaultCandidateTTL = 7 * 24 * time.Hour

// CandidateOptions assembles a candidate after trust evaluation and rule
// compilation. Decision must be allowed; quarantined items never become
// candidates.
type CandidateOptions struct {
	Item          Item
	Extraction    Extraction
	Decision      TrustDecision
	Rule          CompiledRule
	TTL           time.Duration
	Now           time.Time
	ExtractorName string
}

// NewCandidate builds a draft, disabled, log-only candidate. It is deterministic
// for a fixed item, rule, and clock.
func NewCandidate(opts CandidateOptions) (Candidate, error) {
	if !opts.Decision.Allowed {
		reason := strings.TrimSpace(opts.Decision.Reason)
		if reason == "" {
			reason = "source trust policy did not allow this item"
		}
		return Candidate{}, fmt.Errorf("%w: %s", ErrQuarantined, reason)
	}
	if strings.TrimSpace(opts.Item.ID) == "" {
		return Candidate{}, fmt.Errorf("%w: item id is required", ErrInvalid)
	}
	if err := ValidateExtraction(opts.Extraction); err != nil {
		return Candidate{}, err
	}
	if err := ValidateCompiledRule(opts.Rule); err != nil {
		return Candidate{}, err
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultCandidateTTL
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ruleJSON, err := json.Marshal(opts.Rule)
	if err != nil {
		return Candidate{}, fmt.Errorf("%w: encode rule: %v", ErrInvalid, err)
	}
	extractor := strings.TrimSpace(opts.ExtractorName)
	if extractor == "" {
		extractor = "deterministic-rule-compiler"
	}
	candidate := Candidate{
		ID:         candidateID(opts.Item.ID, opts.Rule.Rule.ID),
		ItemID:     opts.Item.ID,
		SiteID:     opts.Rule.Scope.SiteID,
		RuleJSON:   string(ruleJSON),
		Action:     strings.ToLower(strings.TrimSpace(opts.Rule.Rule.Action)),
		State:      CandidateDraft,
		Confidence: opts.Extraction.Confidence,
		Provenance: Provenance{
			SourceID:    strings.TrimSpace(opts.Item.SourceID),
			SourceTrust: opts.Decision.Trust,
			ItemID:      opts.Item.ID,
			Extractor:   extractor,
			References:  opts.Extraction.References,
		},
		TTL:       ttl,
		CreatedAt: now.UTC(),
	}
	if err := ValidateCandidate(candidate); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func candidateID(itemID, ruleID string) string {
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, itemID)
	_, _ = hasher.Write([]byte{'\n'})
	_, _ = io.WriteString(hasher, ruleID)
	return "cand-" + hex.EncodeToString(hasher.Sum(nil))[:16]
}
