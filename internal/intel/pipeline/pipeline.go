// Package pipeline composes feed ingestion, trust evaluation, deterministic
// extraction, rule compilation, and impact estimation into reviewable rule
// candidates. It performs no network I/O and never activates a rule: every
// candidate is disabled, log-only, single-site, and gated by a human decision
// before canary or active rollout.
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
)

const (
	// DefaultMaxCandidatesPerItem bounds candidates yielded by one feed item.
	DefaultMaxCandidatesPerItem = 2
	// HardMaxCandidatesPerItem is the largest configurable per-item bound.
	HardMaxCandidatesPerItem = 16
	// DefaultCanaryPercent is the canary share used by Promote.
	DefaultCanaryPercent = 5.0

	maxReportedErrors       = 8
	maxCorroborationEntries = 1024
	defaultExtractorName    = "intel-pipeline"
)

// Candidate is a compiled intel candidate together with its impact assessment
// and trust decision. The embedded candidate remains the review-first record.
type Candidate struct {
	intel.Candidate
	Decision intel.TrustDecision
	Impact   impact.Assessment
}

// ProfileProvider supplies aggregate traffic profiles for impact estimation.
// It receives the impact view of the candidate so providers can key match
// counters by candidate ID. It must return locally aggregated counters only,
// never raw request data.
type ProfileProvider interface {
	Profiles(ctx context.Context, candidate impact.Candidate) []impact.Profile
}

// ProfileProviderFunc adapts a function to ProfileProvider.
type ProfileProviderFunc func(ctx context.Context, candidate impact.Candidate) []impact.Profile

// Profiles calls the underlying function.
func (f ProfileProviderFunc) Profiles(ctx context.Context, candidate impact.Candidate) []impact.Profile {
	return f(ctx, candidate)
}

// Config assembles a Pipeline. Zero values select secure defaults.
type Config struct {
	Registry             *Registry
	Extractor            Extractor
	Profiles             ProfileProvider
	TrustPolicy          intel.TrustPolicy
	ImpactPolicy         impact.Policy
	TTL                  time.Duration
	Now                  func() time.Time
	CanaryPercent        float64
	MaxCandidatesPerItem int
	ExtractorName        string
}

// Pipeline ingests feed bodies into candidates and gates promotion. Dedupe
// state and cross-source corroboration are kept in memory; callers own any
// persistence.
type Pipeline struct {
	registry      *Registry
	extractor     Extractor
	profiles      ProfileProvider
	trustPolicy   intel.TrustPolicy
	impactPolicy  impact.Policy
	ttl           time.Duration
	now           func() time.Time
	canaryPercent float64
	maxPerItem    int
	extractorName string
	dedupe        *feed.Dedupe
	corroboration *corroborationTracker
}

// New validates configuration and returns a pipeline. No I/O is performed.
func New(config Config) (*Pipeline, error) {
	if config.Registry == nil {
		return nil, fmt.Errorf("%w: registry is required", ErrInvalid)
	}
	if config.Extractor == nil {
		return nil, fmt.Errorf("%w: extractor is required", ErrInvalid)
	}
	trustPolicy := config.TrustPolicy
	if trustPolicy.RequiredCorroboration == 0 {
		trustPolicy = intel.DefaultTrustPolicy()
	}
	if err := config.ImpactPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	ttl := config.TTL
	if ttl == 0 {
		ttl = intel.DefaultCandidateTTL
	}
	if ttl < 0 || ttl > intel.MaxCandidateTTL {
		return nil, fmt.Errorf("%w: candidate TTL must be within (0, %s]", ErrInvalid, intel.MaxCandidateTTL)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	canaryPercent := config.CanaryPercent
	if canaryPercent == 0 {
		canaryPercent = DefaultCanaryPercent
	}
	if canaryPercent < 0 || canaryPercent > 100 {
		return nil, fmt.Errorf("%w: canary percent must be within (0, 100]", ErrInvalid)
	}
	maxPerItem := config.MaxCandidatesPerItem
	if maxPerItem == 0 {
		maxPerItem = DefaultMaxCandidatesPerItem
	}
	if maxPerItem < 0 || maxPerItem > HardMaxCandidatesPerItem {
		return nil, fmt.Errorf("%w: max candidates per item must be within (0, %d]", ErrInvalid, HardMaxCandidatesPerItem)
	}
	extractorName := strings.TrimSpace(config.ExtractorName)
	if extractorName == "" {
		extractorName = defaultExtractorName
	}
	return &Pipeline{
		registry:      config.Registry,
		extractor:     config.Extractor,
		profiles:      config.Profiles,
		trustPolicy:   trustPolicy,
		impactPolicy:  config.ImpactPolicy,
		ttl:           ttl,
		now:           now,
		canaryPercent: canaryPercent,
		maxPerItem:    maxPerItem,
		extractorName: extractorName,
		dedupe:        feed.NewDedupe(),
		corroboration: newCorroborationTracker(maxCorroborationEntries),
	}, nil
}

// Ingest parses one feed body for a registered source, rejects duplicate or
// replayed items, evaluates trust per item, extracts, compiles, and estimates
// impact. It always returns the candidates it produced; a non-nil error
// summarizes bounded per-item rejections and must not be read as "no
// candidates". Nothing is persisted or activated.
func (p *Pipeline) Ingest(ctx context.Context, sourceID string, body []byte, sequence uint64, scope intel.Scope) ([]Candidate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	source, err := p.registry.Resolve(sourceID)
	if err != nil {
		return nil, fmt.Errorf("intel/pipeline: resolve source: %w", err)
	}
	items, err := feed.Parse(source, body)
	if err != nil {
		return nil, err
	}
	accepted, rejected := p.dedupe.Filter(source.ID, sequence, items)
	issues := make([]error, 0, len(rejected))
	for _, rejection := range rejected {
		label := strings.TrimSpace(rejection.Item.ExternalID)
		if label == "" {
			label = strings.TrimSpace(rejection.Item.Link)
		}
		if errors.Is(rejection.Err, feed.ErrDuplicate) || errors.Is(rejection.Err, feed.ErrReplay) {
			issues = append(issues, fmt.Errorf("%w: source %q item %q: %w", ErrDuplicate, source.ID, label, rejection.Err))
			continue
		}
		issues = append(issues, fmt.Errorf("%w: source %q item %q: %w", ErrInvalid, source.ID, label, rejection.Err))
	}

	sources := p.registry.IntelSources()
	candidates := make([]Candidate, 0, len(accepted))
	for _, feedItem := range accepted {
		if err := ctx.Err(); err != nil {
			return candidates, err
		}
		item := mapItem(feedItem)
		item, decision := p.trustDecision(item, sources)
		if !decision.Allowed {
			issues = append(issues, fmt.Errorf("%w: item %q: %s", ErrQuarantined, item.ID, decision.Reason))
			continue
		}

		extractions, err := p.extractor.Extract(ctx, item)
		if err != nil {
			issues = append(issues, fmt.Errorf("%w: item %q: %w", ErrExtractionFailed, item.ID, err))
			continue
		}
		built, itemIssues := p.buildCandidates(ctx, item, decision, extractions, scope)
		candidates = append(candidates, built...)
		issues = append(issues, itemIssues...)
	}
	return candidates, joinIssues(issues)
}

// IngestItem runs trust evaluation, rule compilation, candidate creation, and
// impact estimation for one already-built intel item and its extractions. It
// is the entry point for non-feed pipelines that fetched and normalized HTML
// themselves. It never activates a candidate and performs no I/O.
func (p *Pipeline) IngestItem(ctx context.Context, item intel.Item, extractions []intel.Extraction, scope intel.Scope) ([]Candidate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(item.ID) == "" {
		return nil, fmt.Errorf("%w: item id is required", ErrInvalid)
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	item, decision := p.trustDecision(item, p.registry.IntelSources())
	candidates, issues := p.buildCandidates(ctx, item, decision, extractions, scope)
	return candidates, joinIssues(issues)
}

// trustDecision merges recorded cross-source corroboration into the item and
// evaluates the trust policy. It is the single trust gate for both entry
// points.
func (p *Pipeline) trustDecision(item intel.Item, sources []intel.Source) (intel.Item, intel.TrustDecision) {
	item.CorroboratingSourceIDs = mergeSourceIDs(
		item.CorroboratingSourceIDs,
		p.corroboration.observe(item.ContentHash, item.SourceID),
	)
	return item, p.trustPolicy.EvaluateItem(item, sources)
}

func mergeSourceIDs(existing, extra []string) []string {
	if len(existing) == 0 && len(extra) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(existing)+len(extra))
	merged := make([]string, 0, len(existing)+len(extra))
	for _, group := range [][]string{existing, extra} {
		for _, id := range group {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			merged = append(merged, id)
		}
	}
	sort.Strings(merged)
	return merged
}

// buildCandidates enforces the per-item cap, compiles every extraction, and
// estimates impact. Items denied by the trust policy yield no candidate.
func (p *Pipeline) buildCandidates(ctx context.Context, item intel.Item, decision intel.TrustDecision, extractions []intel.Extraction, scope intel.Scope) ([]Candidate, []error) {
	if !decision.Allowed {
		reason := strings.TrimSpace(decision.Reason)
		if reason == "" {
			reason = "source trust policy did not allow this item"
		}
		return nil, []error{fmt.Errorf("%w: item %q: %s", ErrQuarantined, item.ID, reason)}
	}
	if len(extractions) == 0 {
		return nil, []error{fmt.Errorf("%w: item %q: no extraction supplied", ErrNoSafeRule, item.ID)}
	}

	issues := make([]error, 0, 1)
	if len(extractions) > p.maxPerItem {
		issues = append(issues, fmt.Errorf("%w: item %q yielded %d extractions, capped at %d", ErrLimitExceeded, item.ID, len(extractions), p.maxPerItem))
		extractions = extractions[:p.maxPerItem]
	}
	candidates := make([]Candidate, 0, len(extractions))
	for _, extraction := range extractions {
		rule, err := intel.NewRuleCompiler().Compile(extraction, scope)
		if err != nil {
			if errors.Is(err, intel.ErrNoSafeRule) || errors.Is(err, intel.ErrBroadRule) {
				issues = append(issues, fmt.Errorf("%w: item %q: %w", ErrNoSafeRule, item.ID, err))
				continue
			}
			issues = append(issues, fmt.Errorf("%w: item %q: %w", ErrInvalid, item.ID, err))
			continue
		}
		candidate, err := intel.NewCandidate(intel.CandidateOptions{
			Item:          item,
			Extraction:    extraction,
			Decision:      decision,
			Rule:          rule,
			TTL:           p.ttl,
			Now:           p.now().UTC(),
			ExtractorName: p.extractorName,
		})
		if err != nil {
			issues = append(issues, fmt.Errorf("%w: item %q: %w", ErrInvalid, item.ID, err))
			continue
		}
		candidates = append(candidates, Candidate{
			Candidate: candidate,
			Decision:  decision,
			Impact:    p.estimate(ctx, candidate, rule.Scope),
		})
	}
	return candidates, issues
}

func (p *Pipeline) estimate(ctx context.Context, candidate intel.Candidate, scope intel.Scope) impact.Assessment {
	view := impact.Candidate{
		ID:         candidate.ID,
		SiteID:     scope.SiteID,
		PathPrefix: scope.PathPrefix,
		Methods:    scope.Methods,
		Action:     candidate.Action,
		Approved:   candidate.Provenance.Approved,
	}
	var profiles []impact.Profile
	if p.profiles != nil {
		profiles = p.profiles.Profiles(ctx, view)
	}
	return p.impactPolicy.Estimate(view, profiles)
}

// mapItem converts a normalized feed item into an intel item. Fields the feed
// does not provide (versions, attack vector, exploit status) stay empty rather
// than being invented.
func mapItem(feedItem feed.FeedItem) intel.Item {
	externalIDs := make([]string, 0, len(feedItem.CVEIDs)+len(feedItem.AVDIDs)+len(feedItem.GHSAIDs))
	seen := make(map[string]struct{}, cap(externalIDs))
	for _, family := range [][]string{feedItem.CVEIDs, feedItem.AVDIDs, feedItem.GHSAIDs} {
		for _, id := range family {
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			externalIDs = append(externalIDs, id)
		}
	}
	return intel.Item{
		ID:          itemID(feedItem),
		SourceID:    feedItem.SourceID,
		ExternalIDs: externalIDs,
		Title:       feedItem.Title,
		ContentHash: feedItem.ContentHash,
		PublishedAt: feedItem.Published,
		Products:    append([]string(nil), feedItem.Products...),
		References:  append([]string(nil), feedItem.References...),
		RawExcerpt:  feedItem.Summary,
	}
}

func itemID(feedItem feed.FeedItem) string {
	hasher := sha256.New()
	for _, part := range []string{feedItem.SourceID, feedItem.ExternalID, feedItem.ContentHash} {
		_, _ = hasher.Write([]byte(part))
		_, _ = hasher.Write([]byte{'\n'})
	}
	return "item-" + hex.EncodeToString(hasher.Sum(nil))[:16]
}

func joinIssues(issues []error) error {
	if len(issues) == 0 {
		return nil
	}
	if len(issues) > maxReportedErrors {
		remaining := len(issues) - maxReportedErrors
		issues = append(issues[:maxReportedErrors:maxReportedErrors],
			fmt.Errorf("%w: %d additional items were skipped", ErrLimitExceeded, remaining))
	}
	return errors.Join(issues...)
}

// corroborationTracker remembers which sources reported a content hash so
// community items can be corroborated across ingests. It is bounded and safe
// for concurrent use.
type corroborationTracker struct {
	mu     sync.Mutex
	limit  int
	order  []string
	byHash map[string]map[string]struct{}
}

func newCorroborationTracker(limit int) *corroborationTracker {
	if limit <= 0 {
		limit = maxCorroborationEntries
	}
	return &corroborationTracker{
		limit:  limit,
		byHash: make(map[string]map[string]struct{}),
	}
}

// observe records the reporting source and returns the other sources that
// reported the same content, sorted for deterministic trust decisions.
func (t *corroborationTracker) observe(contentHash, sourceID string) []string {
	contentHash = strings.TrimSpace(contentHash)
	sourceID = strings.TrimSpace(sourceID)
	if contentHash == "" || sourceID == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	reporters, exists := t.byHash[contentHash]
	if !exists {
		if len(t.order) >= t.limit {
			oldest := t.order[0]
			t.order = t.order[1:]
			delete(t.byHash, oldest)
		}
		reporters = make(map[string]struct{}, 2)
		t.byHash[contentHash] = reporters
		t.order = append(t.order, contentHash)
	}
	reporters[sourceID] = struct{}{}
	others := make([]string, 0, len(reporters))
	for id := range reporters {
		if id != sourceID {
			others = append(others, id)
		}
	}
	sort.Strings(others)
	return others
}
