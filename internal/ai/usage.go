package ai

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultUsageStoreMaxEvents = 10000
	maxUsageStoreMaxEvents     = 1_000_000
	maxUsageQueryRange         = 90 * 24 * time.Hour
	maxUsageFutureSkew         = 5 * time.Minute
	maxUsageTokensPerCall      = 1_000_000_000_000
	maxUsageLabelBytes         = 512
)

var (
	ErrUsageRangeInvalid = errors.New("AI usage range is invalid")
	ErrUsageStoreClosed  = errors.New("AI usage store is closed")
)

// UsageEvent is non-sensitive accounting metadata for one provider call. It
// deliberately contains no prompt, response, API key, or endpoint data.
type UsageEvent struct {
	At           time.Time `json:"at"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	TotalTokens  int       `json:"total_tokens"`
}

// UsageRange is an inclusive time window. A zero endpoint is filled from the
// store clock: a zero Start means the beginning of the bounded query window,
// while a zero End means now.
type UsageRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// UsageBreakdown keeps the same accounting dimensions as UsageEvent while
// allowing the dashboard to render provider/model cards without re-reading
// raw events.
type UsageBreakdown struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
	CallCount    int `json:"call_count"`
}

// UsageSnapshot is a bounded, immutable view of a usage query.
type UsageSnapshot struct {
	Range                 UsageRange                `json:"range"`
	InputTokens           int                       `json:"input_tokens"`
	OutputTokens          int                       `json:"output_tokens"`
	TotalTokens           int                       `json:"total_tokens"`
	CallCount             int                       `json:"call_count"`
	InputTokensFormatted  string                    `json:"input_tokens_formatted"`
	OutputTokensFormatted string                    `json:"output_tokens_formatted"`
	TotalTokensFormatted  string                    `json:"total_tokens_formatted"`
	ByProvider            map[string]UsageBreakdown `json:"by_provider,omitempty"`
	ByModel               map[string]UsageBreakdown `json:"by_model,omitempty"`
}

type UsageStoreOptions struct {
	Now       func() time.Time
	MaxEvents int
}

// UsageStore retains a bounded local accounting window. Record is deliberately
// synchronous: it gives callers a deterministic accounting point and avoids a
// background goroutine in the request path. WaitForIdle remains as a stable
// integration seam for callers that may switch to a durable asynchronous
// adapter later.
type UsageStore struct {
	mu        sync.RWMutex
	clock     func() time.Time
	maxEvents int
	events    []UsageEvent
	closed    bool
}

func NewUsageStore(opts UsageStoreOptions) *UsageStore {
	maxEvents := opts.MaxEvents
	if maxEvents == 0 {
		maxEvents = defaultUsageStoreMaxEvents
	}
	if maxEvents < 1 {
		maxEvents = defaultUsageStoreMaxEvents
	}
	if maxEvents > maxUsageStoreMaxEvents {
		maxEvents = maxUsageStoreMaxEvents
	}
	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	return &UsageStore{clock: clock, maxEvents: maxEvents, events: make([]UsageEvent, 0, minInt(maxEvents, 256))}
}

// Record appends an event and evicts the oldest event when the configured
// bound is reached. Invalid negative token counts are ignored so malformed
// provider responses cannot corrupt cumulative totals.
func (s *UsageStore) Record(event UsageEvent) {
	if s == nil {
		return
	}
	if event.InputTokens < 0 || event.OutputTokens < 0 || event.TotalTokens < 0 {
		return
	}
	if event.At.IsZero() {
		event.At = s.clock().UTC()
	} else {
		event.At = event.At.UTC()
	}
	event.Provider = canonicalUsageLabel(event.Provider, "unknown")
	event.Model = canonicalUsageLabel(event.Model, "unknown")
	event.InputTokens = boundedUsageTokens(event.InputTokens)
	event.OutputTokens = boundedUsageTokens(event.OutputTokens)
	event.TotalTokens = boundedUsageTokens(event.TotalTokens)
	if event.TotalTokens == 0 {
		event.TotalTokens = boundedUsageTokens(event.InputTokens + event.OutputTokens)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if len(s.events) >= s.maxEvents {
		copy(s.events, s.events[len(s.events)-s.maxEvents+1:])
		s.events = s.events[:s.maxEvents-1]
	}
	s.events = append(s.events, event)
}

// Snapshot returns aggregate totals for the requested bounded window.
func (s *UsageStore) Snapshot(query UsageRange) (UsageSnapshot, error) {
	if s == nil {
		return UsageSnapshot{}, ErrUsageStoreClosed
	}
	now := s.clock().UTC()
	query, err := normalizeUsageRange(query, now)
	if err != nil {
		return UsageSnapshot{}, err
	}
	s.mu.RLock()
	events := append([]UsageEvent(nil), s.events...)
	s.mu.RUnlock()
	snapshot := UsageSnapshot{Range: query, ByProvider: make(map[string]UsageBreakdown), ByModel: make(map[string]UsageBreakdown)}
	for _, event := range events {
		if event.At.Before(query.Start) || event.At.After(query.End) {
			continue
		}
		total := event.TotalTokens
		if total == 0 {
			total = event.InputTokens + event.OutputTokens
		}
		snapshot.InputTokens += event.InputTokens
		snapshot.OutputTokens += event.OutputTokens
		snapshot.TotalTokens += total
		snapshot.CallCount++
		addUsageBreakdown(snapshot.ByProvider, event.Provider, event.InputTokens, event.OutputTokens, total)
		addUsageBreakdown(snapshot.ByModel, event.Model, event.InputTokens, event.OutputTokens, total)
	}
	snapshot.InputTokensFormatted = FormatUsageNumber(snapshot.InputTokens)
	snapshot.OutputTokensFormatted = FormatUsageNumber(snapshot.OutputTokens)
	snapshot.TotalTokensFormatted = FormatUsageNumber(snapshot.TotalTokens)
	return snapshot, nil
}

// Close prevents new events from being recorded. Existing snapshots remain
// readable, which makes shutdown and final dashboard refresh deterministic.
func (s *UsageStore) Close() error {
	if s == nil {
		return ErrUsageStoreClosed
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *UsageStore) WaitForIdle() {}

func normalizeUsageRange(query UsageRange, now time.Time) (UsageRange, error) {
	now = now.UTC()
	if query.End.IsZero() {
		query.End = now
	} else {
		query.End = query.End.UTC()
	}
	if query.Start.IsZero() {
		query.Start = query.End.Add(-24 * time.Hour)
	} else {
		query.Start = query.Start.UTC()
	}
	if query.Start.After(query.End) || query.End.Sub(query.Start) > maxUsageQueryRange || query.Start.After(now.Add(maxUsageFutureSkew)) || query.End.After(now.Add(maxUsageFutureSkew)) {
		return UsageRange{}, ErrUsageRangeInvalid
	}
	return query, nil
}

func addUsageBreakdown(target map[string]UsageBreakdown, key string, input, output, total int) {
	entry := target[key]
	entry.InputTokens += input
	entry.OutputTokens += output
	entry.TotalTokens += total
	entry.CallCount++
	target[key] = entry
}

func canonicalUsageLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if len(value) <= maxUsageLabelBytes {
		return value
	}
	value = value[:maxUsageLabelBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func boundedUsageTokens(value int) int {
	if value <= 0 {
		return 0
	}
	if value > maxUsageTokensPerCall {
		return maxUsageTokensPerCall
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FormatUsageNumber keeps dashboard counters compact while retaining two
// decimal places for scaled values (for example 2.00K, 1.25M, 1.00B).
func FormatUsageNumber(value int) string {
	const (
		k = 1000
		m = 1000 * k
		b = 1000 * m
	)
	switch {
	case value >= b || value <= -b:
		return fmt.Sprintf("%.2fB", float64(value)/b)
	case value >= m || value <= -m:
		return fmt.Sprintf("%.2fM", float64(value)/m)
	case value >= k || value <= -k:
		return fmt.Sprintf("%.2fK", float64(value)/k)
	default:
		return fmt.Sprintf("%d", value)
	}
}

// UsageEvents returns a stable copy for durable adapters and diagnostics. It
// is intentionally not exposed by the HTTP handler, which only returns the
// aggregate snapshot.
func (s *UsageStore) UsageEvents() []UsageEvent {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := append([]UsageEvent(nil), s.events...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].At.Before(result[j].At) })
	return result
}
