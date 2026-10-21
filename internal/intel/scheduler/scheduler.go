// Package scheduler polls vulnerability intelligence feeds on a bounded
// interval, applies conditional requests and per-source backoff, and hands
// normalized, deduplicated items to a sink.
//
// The scheduler performs no network I/O and no parsing of its own: fetching,
// feed parsing, normalization, and deduplication are delegated to injected
// implementations. Polling runs in the caller's goroutine and every poll joins
// its workers before returning, so a cancelled Run leaves no goroutines
// behind. Polls never run concurrently with themselves.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
)

const (
	// DefaultInterval is the poll interval used when Config.Interval is zero.
	DefaultInterval = 15 * time.Minute
	// MinInterval is the smallest accepted poll interval.
	MinInterval = 10 * time.Second
	// MaxInterval is the largest accepted poll interval.
	MaxInterval = 24 * time.Hour

	// DefaultMaxConcurrent is the worker count used when Config.MaxConcurrent
	// is zero.
	DefaultMaxConcurrent = 4
	// HardMaxConcurrent is the largest accepted worker count.
	HardMaxConcurrent = 32

	// DefaultMaxItemsPerSource bounds accepted items when
	// Config.MaxItemsPerSource is zero.
	DefaultMaxItemsPerSource = 200
	// HardMaxItemsPerSource is the largest accepted per-source item bound.
	HardMaxItemsPerSource = feed.MaxItems

	// DefaultBackoff is the retry delay applied after the first failure when
	// Config.Backoff is zero. Each consecutive failure doubles it.
	DefaultBackoff = 30 * time.Second
	// MaxBackoff is the upper bound for the exponentially grown retry delay.
	MaxBackoff = time.Hour
)

// Errors returned by the scheduler. Callers can use errors.Is to distinguish
// configuration mistakes from per-source poll failures.
var (
	// ErrInvalid reports malformed configuration, sources, or options.
	ErrInvalid = errors.New("intel/scheduler: invalid input")
	// ErrSourceProvider reports a provider that could not list sources.
	ErrSourceProvider = errors.New("intel/scheduler: source provider failed")
	// ErrSource reports one source that failed to fetch, parse, or deliver.
	// A single failing source never aborts the rest of the poll.
	ErrSource = errors.New("intel/scheduler: source poll failed")
)

// Config controls polling. Zero values select the documented defaults; values
// outside the accepted range are rejected by New rather than silently clamped.
type Config struct {
	// Interval is the delay between polls.
	Interval time.Duration
	// MaxConcurrent bounds in-flight fetches across all sources.
	MaxConcurrent int
	// MaxItemsPerSource truncates a feed before deduplication and delivery.
	MaxItemsPerSource int
	// Backoff is the base retry delay for a failing source. Consecutive
	// failures double it up to MaxBackoff.
	Backoff time.Duration
	// Now returns the current time. It exists so tests and embedders can use a
	// deterministic clock; nil selects time.Now.
	Now func() time.Time
}

func (c Config) normalize() (Config, error) {
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
	if c.Interval < MinInterval || c.Interval > MaxInterval {
		return Config{}, fmt.Errorf("%w: interval must be between %s and %s", ErrInvalid, MinInterval, MaxInterval)
	}

	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = DefaultMaxConcurrent
	}
	if c.MaxConcurrent < 1 || c.MaxConcurrent > HardMaxConcurrent {
		return Config{}, fmt.Errorf("%w: max concurrent must be between 1 and %d", ErrInvalid, HardMaxConcurrent)
	}

	if c.MaxItemsPerSource == 0 {
		c.MaxItemsPerSource = DefaultMaxItemsPerSource
	}
	if c.MaxItemsPerSource < 1 || c.MaxItemsPerSource > HardMaxItemsPerSource {
		return Config{}, fmt.Errorf("%w: max items per source must be between 1 and %d", ErrInvalid, HardMaxItemsPerSource)
	}

	if c.Backoff == 0 {
		c.Backoff = DefaultBackoff
	}
	if c.Backoff < 0 || c.Backoff > MaxBackoff {
		return Config{}, fmt.Errorf("%w: backoff must be between 0 and %s", ErrInvalid, MaxBackoff)
	}

	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}

// Request describes one conditional feed request. ETag and LastModified carry
// the validators from the previous response; both are empty on a first fetch.
type Request struct {
	URL          string
	ETag         string
	LastModified string
}

// Response is the result of one feed fetch. Implementations must set
// NotModified for a 304 response and return an error for every other non-2xx
// status; StatusCode is retained for logging by the embedder.
type Response struct {
	StatusCode   int
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
}

// Fetcher retrieves one feed. Implementations must honor ctx and be safe for
// concurrent use, because a poll calls Fetch from up to Config.MaxConcurrent
// workers.
type Fetcher interface {
	Fetch(ctx context.Context, request Request) (Response, error)
}

// FetcherFunc adapts a function to Fetcher.
type FetcherFunc func(ctx context.Context, request Request) (Response, error)

// Fetch calls the underlying function.
func (f FetcherFunc) Fetch(ctx context.Context, request Request) (Response, error) {
	return f(ctx, request)
}

// SourceProvider lists the configured feeds. Disabled sources are returned
// with Enabled false and are skipped by the scheduler, so a provider can reuse
// the same shape as the operator configuration.
type SourceProvider interface {
	Sources(ctx context.Context) ([]feed.Source, error)
}

// SourceProviderFunc adapts a function to SourceProvider.
type SourceProviderFunc func(ctx context.Context) ([]feed.Source, error)

// Sources calls the underlying function.
func (f SourceProviderFunc) Sources(ctx context.Context) ([]feed.Source, error) {
	return f(ctx)
}

// Sink receives normalized, deduplicated items for one source. Deliver is
// called at most once per source per poll and only for non-empty batches. It
// must be safe for concurrent use: polls deliver different sources in
// parallel.
//
// A delivery error is reported as a source failure and triggers backoff. The
// batch is not retried automatically because the deduplication state has
// already advanced; an embedder that needs durable delivery should persist
// items inside Deliver before acknowledging them.
type Sink interface {
	Deliver(ctx context.Context, source feed.Source, items []feed.FeedItem) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, source feed.Source, items []feed.FeedItem) error

// Deliver calls the underlying function.
func (f SinkFunc) Deliver(ctx context.Context, source feed.Source, items []feed.FeedItem) error {
	return f(ctx, source, items)
}

// Result reports one source's outcome in a poll. Err is nil on success and on
// a skipped source; Skipped reports that per-source backoff deferred the poll.
type Result struct {
	Source      feed.Source
	Sequence    uint64
	Skipped     bool
	NotModified bool
	Accepted    int
	Rejected    int
	Err         error
}

// Report summarizes one poll. Results is ordered by source ID.
type Report struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Results    []Result
}

// Accepted returns the number of items delivered across all sources.
func (r Report) Accepted() int {
	total := 0
	for _, result := range r.Results {
		total += result.Accepted
	}
	return total
}

// Rejected returns the number of duplicate, replayed, or invalid items.
func (r Report) Rejected() int {
	total := 0
	for _, result := range r.Results {
		total += result.Rejected
	}
	return total
}

// Options assembles a Runner. Provider, Fetcher, and Sink are required.
type Options struct {
	Config   Config
	Provider SourceProvider
	Fetcher  Fetcher
	Sink     Sink
	// Dedupe carries replay protection across polls. A nil value starts with
	// fresh state.
	Dedupe *feed.Dedupe
}

// Runner polls feeds. A Runner must be driven by one loop at a time: PollOnce
// is not safe to call concurrently with itself for the same Runner, because
// out-of-order batches from the same source would be rejected as replays.
// PollOnce and Run use the source state under a mutex, so a concurrent call
// causes no data race, but Run is the supported entry point for continuous
// polling.
type Runner struct {
	config    Config
	provider  SourceProvider
	fetcher   Fetcher
	sink      Sink
	dedupe    *feed.Dedupe
	newTicker func(time.Duration) ticker

	mu     sync.Mutex
	states map[string]*sourceState
}

// sourceState is the per-source polling state: conditional validators, the
// last sequence number, and the current backoff window.
type sourceState struct {
	etag         string
	lastModified string
	sequence     uint64
	failures     int
	retryAt      time.Time
}

// New validates options and returns a Runner. It performs no I/O.
func New(options Options) (*Runner, error) {
	config, err := options.Config.normalize()
	if err != nil {
		return nil, err
	}
	if options.Provider == nil {
		return nil, fmt.Errorf("%w: source provider is required", ErrInvalid)
	}
	if options.Fetcher == nil {
		return nil, fmt.Errorf("%w: fetcher is required", ErrInvalid)
	}
	if options.Sink == nil {
		return nil, fmt.Errorf("%w: sink is required", ErrInvalid)
	}
	dedupe := options.Dedupe
	if dedupe == nil {
		dedupe = feed.NewDedupe()
	}
	return &Runner{
		config:    config,
		provider:  options.Provider,
		fetcher:   options.Fetcher,
		sink:      options.Sink,
		dedupe:    dedupe,
		newTicker: systemTickerFactory,
		states:    make(map[string]*sourceState),
	}, nil
}

// Run polls immediately and then once per Config.Interval until ctx is done.
// It returns ctx.Err() on cancellation. Source failures are isolated: they are
// recorded in the Report returned by each poll and never stop the loop.
func (r *Runner) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := r.PollOnce(ctx); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	ticker := r.newTicker(r.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C():
			if _, err := r.PollOnce(ctx); err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
}

// PollOnce fetches every enabled source once and returns when all workers have
// finished. Per-source failures are reported in Report.Results and joined into
// the returned error; provider failures and context cancellation abort the
// poll. A source inside its backoff window is reported as skipped.
func (r *Runner) PollOnce(ctx context.Context) (Report, error) {
	report := Report{StartedAt: r.config.Now()}
	if ctx == nil {
		return report, fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}

	sources, err := r.provider.Sources(ctx)
	if err != nil {
		report.FinishedAt = r.config.Now()
		return report, fmt.Errorf("%w: %w", ErrSourceProvider, err)
	}

	enabled := make([]feed.Source, 0, len(sources))
	for _, source := range sources {
		if source.Enabled {
			enabled = append(enabled, source)
		}
	}
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].ID < enabled[j].ID })

	report.Results = make([]Result, len(enabled))
	pollable := make([]int, 0, len(enabled))
	seen := make(map[string]struct{}, len(enabled))
	for index, source := range enabled {
		report.Results[index] = Result{Source: source}
		if _, duplicate := seen[source.ID]; duplicate {
			report.Results[index].Err = fmt.Errorf("%w: duplicate source id %q", ErrInvalid, source.ID)
			continue
		}
		seen[source.ID] = struct{}{}
		pollable = append(pollable, index)
	}

	r.pollSources(ctx, report.Results, pollable)

	report.FinishedAt = r.config.Now()
	if err := ctx.Err(); err != nil {
		return report, err
	}
	return report, joinResultErrors(report.Results)
}

// pollSources runs bounded workers over the pollable result indexes. Results
// indexes are written by exactly one goroutine, so no lock is needed. The
// dispatcher stops on cancellation and every worker is joined before return.
func (r *Runner) pollSources(ctx context.Context, results []Result, indexes []int) {
	workers := r.config.MaxConcurrent
	if workers > len(indexes) {
		workers = len(indexes)
	}
	if workers == 0 {
		return
	}

	dispatched := make([]bool, len(results))
	jobs := make(chan int)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for index := range jobs {
				results[index] = r.pollSource(ctx, results[index].Source)
			}
		}()
	}

	cancelled := false
dispatch:
	for _, index := range indexes {
		select {
		case <-ctx.Done():
			cancelled = true
			break dispatch
		case jobs <- index:
			dispatched[index] = true
		}
	}
	close(jobs)
	wait.Wait()

	if cancelled {
		for _, index := range indexes {
			if !dispatched[index] {
				results[index].Err = ctx.Err()
			}
		}
	}
}

// pollSource performs one conditional fetch and commits the resulting items.
func (r *Runner) pollSource(ctx context.Context, source feed.Source) Result {
	result := Result{Source: source}
	if err := validateSource(source); err != nil {
		result.Err = err
		return result
	}
	if ctx.Err() != nil {
		result.Err = ctx.Err()
		return result
	}

	now := r.config.Now()
	etag, lastModified, skip := r.beginPoll(source.ID, now)
	if skip {
		result.Skipped = true
		return result
	}

	response, err := r.fetcher.Fetch(ctx, Request{
		URL:          source.URL,
		ETag:         etag,
		LastModified: lastModified,
	})
	if err != nil {
		if ctx.Err() != nil {
			result.Err = ctx.Err()
			return result
		}
		r.recordFailure(source.ID, now)
		result.Err = fmt.Errorf("%w: source %q: fetch: %w", ErrSource, source.ID, err)
		return result
	}
	if ctx.Err() != nil {
		result.Err = ctx.Err()
		return result
	}

	if response.NotModified {
		r.recordSuccess(source.ID, response.ETag, response.LastModified)
		result.NotModified = true
		return result
	}

	items, err := feed.Parse(source, response.Body)
	if err != nil {
		r.recordFailure(source.ID, now)
		result.Err = fmt.Errorf("%w: source %q: parse: %w", ErrSource, source.ID, err)
		return result
	}
	if len(items) > r.config.MaxItemsPerSource {
		items = items[:r.config.MaxItemsPerSource]
	}

	sequence := r.nextSequence(source.ID)
	accepted, rejected := r.dedupe.Filter(source.ID, sequence, items)
	result.Sequence = sequence
	result.Rejected = len(rejected)

	if len(accepted) > 0 {
		if err := r.sink.Deliver(ctx, source, accepted); err != nil {
			if ctx.Err() != nil {
				result.Err = ctx.Err()
				return result
			}
			r.recordFailure(source.ID, now)
			result.Err = fmt.Errorf("%w: source %q: deliver: %w", ErrSource, source.ID, err)
			return result
		}
	}
	r.recordSuccess(source.ID, response.ETag, response.LastModified)
	result.Accepted = len(accepted)
	return result
}

// beginPoll returns the stored validators and reports whether the source is
// still inside its backoff window.
func (r *Runner) beginPoll(sourceID string, now time.Time) (string, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.stateLocked(sourceID)
	if !state.retryAt.IsZero() && now.Before(state.retryAt) {
		return "", "", true
	}
	return state.etag, state.lastModified, false
}

// nextSequence advances the per-source sequence used for replay rejection.
func (r *Runner) nextSequence(sourceID string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.stateLocked(sourceID)
	state.sequence++
	return state.sequence
}

// recordSuccess clears the failure window and refreshes conditional
// validators. Empty validators from the server never erase known ones.
func (r *Runner) recordSuccess(sourceID, etag, lastModified string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.stateLocked(sourceID)
	if etag != "" {
		state.etag = etag
	}
	if lastModified != "" {
		state.lastModified = lastModified
	}
	state.failures = 0
	state.retryAt = time.Time{}
}

// recordFailure grows the per-source backoff. The delay starts at
// Config.Backoff and doubles per consecutive failure up to MaxBackoff.
func (r *Runner) recordFailure(sourceID string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.stateLocked(sourceID)
	state.failures++
	delay := r.config.Backoff
	for range state.failures - 1 {
		if delay >= MaxBackoff {
			break
		}
		delay *= 2
	}
	if delay > MaxBackoff {
		delay = MaxBackoff
	}
	state.retryAt = now.Add(delay)
}

func (r *Runner) stateLocked(sourceID string) *sourceState {
	state := r.states[sourceID]
	if state == nil {
		state = &sourceState{}
		r.states[sourceID] = state
	}
	return state
}

func validateSource(source feed.Source) error {
	id := strings.TrimSpace(source.ID)
	if id == "" {
		return fmt.Errorf("%w: source id is required", ErrInvalid)
	}
	if len(id) > 128 || strings.ContainsFunc(id, unicode.IsControl) {
		return fmt.Errorf("%w: source id %q is malformed", ErrInvalid, id)
	}
	if strings.TrimSpace(source.URL) == "" {
		return fmt.Errorf("%w: source %q has no url", ErrInvalid, id)
	}
	return nil
}

func joinResultErrors(results []Result) error {
	errs := make([]error, 0, len(results))
	for _, result := range results {
		if result.Err != nil {
			errs = append(errs, result.Err)
		}
	}
	return errors.Join(errs...)
}

// ticker abstracts time.Ticker so tests can drive Run without wall time.
type ticker interface {
	C() <-chan time.Time
	Stop()
}

type systemTicker struct {
	ticker *time.Ticker
}

func (t systemTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t systemTicker) Stop() {
	t.ticker.Stop()
}

func systemTickerFactory(interval time.Duration) ticker {
	return systemTicker{ticker: time.NewTicker(interval)}
}
