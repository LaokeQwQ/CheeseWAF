package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
)

const testFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Vendor advisories</title>
    <link>https://vendor.example/feed.xml</link>
    <item>
      <title>CVE-2024-12345 in Acme Widget</title>
      <link>https://vendor.example/advisories/1</link>
      <guid isPermaLink="false">adv-1</guid>
      <description>Exploit details for CVE-2024-12345.</description>
    </item>
    <item>
      <title>Plain advisory</title>
      <link>https://vendor.example/advisories/2</link>
      <guid isPermaLink="false">adv-2</guid>
      <description>Plain item.</description>
    </item>
  </channel>
</rss>`

func testSource(id string) feed.Source {
	return feed.Source{
		ID:      id,
		Name:    id,
		URL:     "https://vendor.example/" + id + ".xml",
		Enabled: true,
	}
}

type fakeProvider struct {
	sources []feed.Source
	err     error
}

func (p *fakeProvider) Sources(ctx context.Context) ([]feed.Source, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]feed.Source(nil), p.sources...), p.err
}

type fakeFetcher struct {
	fn func(ctx context.Context, request Request) (Response, error)

	mu    sync.Mutex
	calls []Request
}

func (f *fakeFetcher) Fetch(ctx context.Context, request Request) (Response, error) {
	if f == nil || f.fn == nil {
		return Response{}, errors.New("fake fetcher is not configured")
	}
	f.mu.Lock()
	f.calls = append(f.calls, request)
	f.mu.Unlock()
	return f.fn(ctx, request)
}

func (f *fakeFetcher) requested() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.calls...)
}

func (f *fakeFetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type deliveredBatch struct {
	source feed.Source
	items  []feed.FeedItem
}

type recordingSink struct {
	err error

	mu      sync.Mutex
	batches []deliveredBatch
}

func (s *recordingSink) Deliver(ctx context.Context, source feed.Source, items []feed.FeedItem) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, deliveredBatch{source: source, items: append([]feed.FeedItem(nil), items...)})
	return nil
}

func (s *recordingSink) delivered() []deliveredBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]deliveredBatch(nil), s.batches...)
}

func newRunner(t *testing.T, options Options) *Runner {
	t.Helper()
	runner, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return runner
}

func TestNewDefaultsAndBounds(t *testing.T) {
	runner := newRunner(t, Options{
		Provider: &fakeProvider{},
		Fetcher:  &fakeFetcher{fn: nil},
		Sink:     &recordingSink{},
	})
	if runner.config.Interval != DefaultInterval {
		t.Fatalf("interval = %s, want %s", runner.config.Interval, DefaultInterval)
	}
	if runner.config.MaxConcurrent != DefaultMaxConcurrent {
		t.Fatalf("max concurrent = %d, want %d", runner.config.MaxConcurrent, DefaultMaxConcurrent)
	}
	if runner.config.MaxItemsPerSource != DefaultMaxItemsPerSource {
		t.Fatalf("max items = %d, want %d", runner.config.MaxItemsPerSource, DefaultMaxItemsPerSource)
	}
	if runner.config.Backoff != DefaultBackoff {
		t.Fatalf("backoff = %s, want %s", runner.config.Backoff, DefaultBackoff)
	}
	if runner.dedupe == nil {
		t.Fatal("dedupe state is nil")
	}

	base := Options{
		Provider: &fakeProvider{},
		Fetcher:  &fakeFetcher{fn: nil},
		Sink:     &recordingSink{},
	}
	tests := []struct {
		name   string
		config Config
	}{
		{"interval too small", Config{Interval: time.Second}},
		{"interval too large", Config{Interval: MaxInterval + time.Second}},
		{"concurrency too high", Config{MaxConcurrent: HardMaxConcurrent + 1}},
		{"concurrency negative", Config{MaxConcurrent: -1}},
		{"items too high", Config{MaxItemsPerSource: HardMaxItemsPerSource + 1}},
		{"items negative", Config{MaxItemsPerSource: -1}},
		{"backoff negative", Config{Backoff: -time.Second}},
		{"backoff too large", Config{Backoff: MaxBackoff + time.Second}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			options.Config = test.config
			if _, err := New(options); !errors.Is(err, ErrInvalid) {
				t.Fatalf("New error = %v, want ErrInvalid", err)
			}
		})
	}

	if _, err := New(Options{Fetcher: base.Fetcher, Sink: base.Sink}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing provider error = %v, want ErrInvalid", err)
	}
	if _, err := New(Options{Provider: base.Provider, Sink: base.Sink}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing fetcher error = %v, want ErrInvalid", err)
	}
	if _, err := New(Options{Provider: base.Provider, Fetcher: base.Fetcher}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing sink error = %v, want ErrInvalid", err)
	}
}

func TestPollOnceDeliversNormalizedItems(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{
		testSource("b"),
		{ID: "disabled", URL: "https://vendor.example/disabled.xml", Enabled: false},
		testSource("a"),
	}}
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		return Response{StatusCode: 200, Body: []byte(testFeed), ETag: `"v1"`}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: sink})

	report, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("results = %d, want 2 enabled sources", len(report.Results))
	}
	if report.Results[0].Source.ID != "a" || report.Results[1].Source.ID != "b" {
		t.Fatalf("results are not sorted by id: %q, %q", report.Results[0].Source.ID, report.Results[1].Source.ID)
	}
	for _, result := range report.Results {
		if result.Err != nil {
			t.Fatalf("source %q: %v", result.Source.ID, result.Err)
		}
		if result.Sequence != 1 {
			t.Fatalf("source %q sequence = %d, want 1", result.Source.ID, result.Sequence)
		}
		if result.Accepted != 2 || result.Rejected != 0 {
			t.Fatalf("source %q accepted=%d rejected=%d, want 2/0", result.Source.ID, result.Accepted, result.Rejected)
		}
	}
	if report.Accepted() != 4 || report.Rejected() != 0 {
		t.Fatalf("report totals accepted=%d rejected=%d, want 4/0", report.Accepted(), report.Rejected())
	}
	if report.FinishedAt.Before(report.StartedAt) {
		t.Fatalf("finished %s is before started %s", report.FinishedAt, report.StartedAt)
	}

	batches := sink.delivered()
	if len(batches) != 2 {
		t.Fatalf("batches = %d, want 2", len(batches))
	}
	for _, batch := range batches {
		if len(batch.items) != 2 {
			t.Fatalf("batch for %q has %d items, want 2", batch.source.ID, len(batch.items))
		}
		for _, item := range batch.items {
			if item.SourceID != batch.source.ID {
				t.Fatalf("item source = %q, want %q", item.SourceID, batch.source.ID)
			}
			if item.ContentHash == "" {
				t.Fatal("item was not normalized: empty content hash")
			}
		}
	}
}

func TestPollOnceTruncatesItemsPerSource(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("vendor")}}
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		return Response{Body: []byte(testFeed)}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{
		Config:   Config{MaxItemsPerSource: 1},
		Provider: provider,
		Fetcher:  fetcher,
		Sink:     sink,
	})

	report, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if report.Accepted() != 1 {
		t.Fatalf("accepted = %d, want 1", report.Accepted())
	}
	if batches := sink.delivered(); len(batches) != 1 || len(batches[0].items) != 1 {
		t.Fatalf("delivered batches = %+v, want one single-item batch", batches)
	}
}

func TestPollOnceUsesConditionalValidators(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("vendor")}}
	var calls int32
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return Response{
				StatusCode:   200,
				Body:         []byte(testFeed),
				ETag:         `"v1"`,
				LastModified: "Mon, 02 Jan 2024 15:04:05 GMT",
			}, nil
		}
		return Response{StatusCode: 304, NotModified: true}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: sink})

	if _, err := runner.PollOnce(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	report, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if !report.Results[0].NotModified {
		t.Fatal("second poll was not reported as not modified")
	}
	if report.Results[0].Accepted != 0 || report.Results[0].Sequence != 0 {
		t.Fatalf("not-modified poll accepted=%d sequence=%d, want 0/0", report.Results[0].Accepted, report.Results[0].Sequence)
	}

	requests := fetcher.requested()
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if requests[0].ETag != "" || requests[0].LastModified != "" {
		t.Fatalf("first request sent validators: %+v", requests[0])
	}
	if requests[1].ETag != `"v1"` {
		t.Fatalf("second request ETag = %q, want %q", requests[1].ETag, `"v1"`)
	}
	if requests[1].LastModified != "Mon, 02 Jan 2024 15:04:05 GMT" {
		t.Fatalf("second request Last-Modified = %q", requests[1].LastModified)
	}
	if batches := sink.delivered(); len(batches) != 1 {
		t.Fatalf("batches = %d, want 1", len(batches))
	}
}

func TestPollOnceRejectsDuplicatesAcrossPolls(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("vendor")}}
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		return Response{Body: []byte(testFeed)}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: sink})

	first, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	second, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}

	if first.Accepted() != 2 {
		t.Fatalf("first accepted = %d, want 2", first.Accepted())
	}
	if second.Accepted() != 0 || second.Rejected() != 2 {
		t.Fatalf("second accepted=%d rejected=%d, want 0/2", second.Accepted(), second.Rejected())
	}
	if second.Results[0].Sequence != first.Results[0].Sequence+1 {
		t.Fatalf("sequence = %d, want %d", second.Results[0].Sequence, first.Results[0].Sequence+1)
	}
	if batches := sink.delivered(); len(batches) != 1 || len(batches[0].items) != 2 {
		t.Fatalf("batches = %+v, want one batch of two items", batches)
	}
}

func TestPollOnceIsolatesSourceFailures(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("bad"), testSource("good")}}
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		if strings.Contains(request.URL, "bad") {
			return Response{}, errors.New("connection refused")
		}
		return Response{Body: []byte(testFeed)}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: sink})

	report, err := runner.PollOnce(context.Background())
	if err == nil {
		t.Fatal("PollOnce returned nil error for a failing source")
	}
	if !errors.Is(err, ErrSource) {
		t.Fatalf("error = %v, want ErrSource", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error %q does not include the fetch cause", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(report.Results))
	}
	if report.Results[0].Source.ID != "bad" || report.Results[0].Err == nil {
		t.Fatalf("bad source result = %+v", report.Results[0])
	}
	if report.Results[1].Source.ID != "good" || report.Results[1].Err != nil {
		t.Fatalf("good source result = %+v", report.Results[1])
	}
	if report.Results[1].Accepted != 2 {
		t.Fatalf("good source accepted = %d, want 2", report.Results[1].Accepted)
	}
	if batches := sink.delivered(); len(batches) != 1 || batches[0].source.ID != "good" {
		t.Fatalf("batches = %+v, want only the healthy source", batches)
	}
}

func TestPollOnceReportsParseAndDeliveryFailures(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("vendor")}}
	sinkErr := errors.New("sink unavailable")

	t.Run("parse", func(t *testing.T) {
		fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
			return Response{Body: []byte("<html>not a feed</html>")}, nil
		}}
		sink := &recordingSink{}
		runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: sink})
		report, err := runner.PollOnce(context.Background())
		if !errors.Is(err, ErrSource) || !errors.Is(err, feed.ErrUnsupportedFormat) {
			t.Fatalf("error = %v, want ErrSource wrapping ErrUnsupportedFormat", err)
		}
		if report.Results[0].Err == nil || report.Results[0].Accepted != 0 {
			t.Fatalf("result = %+v", report.Results[0])
		}
	})

	t.Run("delivery", func(t *testing.T) {
		fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
			return Response{Body: []byte(testFeed)}, nil
		}}
		sink := &recordingSink{err: sinkErr}
		runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: sink})
		report, err := runner.PollOnce(context.Background())
		if !errors.Is(err, ErrSource) || !errors.Is(err, sinkErr) {
			t.Fatalf("error = %v, want ErrSource wrapping the sink error", err)
		}
		if report.Results[0].Accepted != 0 {
			t.Fatalf("accepted = %d, want 0 on delivery failure", report.Results[0].Accepted)
		}
	})
}

func TestPollOnceHonorsBackoff(t *testing.T) {
	var now time.Time
	now = time.Date(2024, time.January, 2, 3, 0, 0, 0, time.UTC)
	provider := &fakeProvider{sources: []feed.Source{testSource("flaky"), testSource("steady")}}
	flakyCalls := 0
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		if strings.Contains(request.URL, "flaky") {
			flakyCalls++
			return Response{}, errors.New("boom")
		}
		return Response{Body: []byte(testFeed)}, nil
	}}
	runner := newRunner(t, Options{
		Config:   Config{Backoff: time.Minute, Now: func() time.Time { return now }},
		Provider: provider,
		Fetcher:  fetcher,
		Sink:     &recordingSink{},
	})

	if _, err := runner.PollOnce(context.Background()); err == nil {
		t.Fatal("first poll returned nil error")
	}
	if flakyCalls != 1 {
		t.Fatalf("flaky calls = %d, want 1", flakyCalls)
	}

	now = now.Add(30 * time.Second)
	report, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("second poll error = %v, want nil while backing off", err)
	}
	if !report.Results[0].Skipped {
		t.Fatalf("flaky source was not skipped: %+v", report.Results[0])
	}
	if flakyCalls != 1 {
		t.Fatalf("flaky calls = %d, want 1 while backing off", flakyCalls)
	}
	if report.Results[1].Err != nil || report.Results[1].Rejected != 2 {
		t.Fatalf("steady source result = %+v, want a successful duplicate-only poll", report.Results[1])
	}

	now = now.Add(31 * time.Second)
	if _, err := runner.PollOnce(context.Background()); err == nil {
		t.Fatal("third poll error = nil, want retry failure")
	}
	if flakyCalls != 2 {
		t.Fatalf("flaky calls = %d, want 2 after backoff elapsed", flakyCalls)
	}

	now = now.Add(2 * time.Minute)
	if _, err := runner.PollOnce(context.Background()); err == nil {
		t.Fatal("fourth poll error = nil, want retry failure")
	}
	if flakyCalls != 3 {
		t.Fatalf("flaky calls = %d, want 3 after doubled backoff", flakyCalls)
	}
}

func TestPollOnceBoundsConcurrency(t *testing.T) {
	sources := make([]feed.Source, 0, 8)
	for index := range 8 {
		sources = append(sources, testSource("source-"+string(rune('a'+index))))
	}
	provider := &fakeProvider{sources: sources}

	var active, maxActive int32
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		current := atomic.AddInt32(&active, 1)
		for {
			seen := atomic.LoadInt32(&maxActive)
			if current <= seen || atomic.CompareAndSwapInt32(&maxActive, seen, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return Response{Body: []byte(testFeed)}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{
		Config:   Config{MaxConcurrent: 2},
		Provider: provider,
		Fetcher:  fetcher,
		Sink:     sink,
	})

	report, err := runner.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if len(report.Results) != 8 || report.Accepted() != 16 {
		t.Fatalf("results=%d accepted=%d, want 8/16", len(report.Results), report.Accepted())
	}
	if got := atomic.LoadInt32(&maxActive); got > 2 {
		t.Fatalf("max in-flight fetches = %d, want <= 2", got)
	}
	if fetcher.count() != 8 {
		t.Fatalf("fetch calls = %d, want 8", fetcher.count())
	}
}

func TestPollOnceCancellation(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("a"), testSource("b"), testSource("c")}}
	started := make(chan struct{}, len(provider.sources))
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		started <- struct{}{}
		<-ctx.Done()
		return Response{}, ctx.Err()
	}}
	runner := newRunner(t, Options{
		Config:   Config{MaxConcurrent: 1},
		Provider: provider,
		Fetcher:  fetcher,
		Sink:     &recordingSink{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var report Report
	var pollErr error
	go func() {
		defer close(done)
		report, pollErr = runner.PollOnce(ctx)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first fetch did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollOnce did not return after cancellation")
	}
	if !errors.Is(pollErr, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", pollErr)
	}
	if len(report.Results) != len(provider.sources) {
		t.Fatalf("results = %d, want %d", len(report.Results), len(provider.sources))
	}
	for _, result := range report.Results {
		if !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("source %q error = %v, want context.Canceled", result.Source.ID, result.Err)
		}
	}
}

func TestPollOnceProviderFailure(t *testing.T) {
	provider := &fakeProvider{err: errors.New("config unreadable")}
	runner := newRunner(t, Options{
		Provider: provider,
		Fetcher:  &fakeFetcher{fn: nil},
		Sink:     &recordingSink{},
	})
	report, err := runner.PollOnce(context.Background())
	if !errors.Is(err, ErrSourceProvider) {
		t.Fatalf("error = %v, want ErrSourceProvider", err)
	}
	if !strings.Contains(err.Error(), "config unreadable") {
		t.Fatalf("error %q lost the provider cause", err)
	}
	if len(report.Results) != 0 {
		t.Fatalf("results = %d, want 0", len(report.Results))
	}
	if report.FinishedAt.Before(report.StartedAt) {
		t.Fatalf("finished %s is before started %s", report.FinishedAt, report.StartedAt)
	}
}

func TestPollOnceRejectsInvalidAndDuplicateSources(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{
		{ID: "dup", URL: "https://vendor.example/one.xml", Enabled: true},
		{ID: "dup", URL: "https://vendor.example/two.xml", Enabled: true},
		{ID: "no-url", Enabled: true},
	}}
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		return Response{Body: []byte(testFeed)}, nil
	}}
	runner := newRunner(t, Options{Provider: provider, Fetcher: fetcher, Sink: &recordingSink{}})

	report, err := runner.PollOnce(context.Background())
	if err == nil {
		t.Fatal("PollOnce returned nil error")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	if len(report.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(report.Results))
	}
	if report.Results[0].Err != nil || report.Results[0].Accepted != 2 {
		t.Fatalf("first source result = %+v, want it polled", report.Results[0])
	}
	if report.Results[1].Err == nil {
		t.Fatalf("duplicate source was not flagged: %+v", report.Results[1])
	}
	if report.Results[2].Err == nil {
		t.Fatalf("missing url result was not flagged: %+v", report.Results[2])
	}
	if fetcher.count() != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetcher.count())
	}
}

type fakeTicker struct {
	ch      chan time.Time
	stopped atomic.Bool
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }
func (t *fakeTicker) Stop()               { t.stopped.Store(true) }

func TestRunPollsOnIntervalUntilCancelled(t *testing.T) {
	provider := &fakeProvider{sources: []feed.Source{testSource("vendor")}}
	polls := make(chan struct{}, 8)
	fetcher := &fakeFetcher{fn: func(ctx context.Context, request Request) (Response, error) {
		polls <- struct{}{}
		return Response{Body: []byte(testFeed)}, nil
	}}
	sink := &recordingSink{}
	runner := newRunner(t, Options{
		Config:   Config{Interval: time.Minute, MaxConcurrent: 1},
		Provider: provider,
		Fetcher:  fetcher,
		Sink:     sink,
	})

	fake := &fakeTicker{ch: make(chan time.Time)}
	tickerReady := make(chan time.Duration, 1)
	runner.newTicker = func(interval time.Duration) ticker {
		tickerReady <- interval
		return fake
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- runner.Run(ctx) }()

	waitForPoll := func(label string) {
		t.Helper()
		select {
		case <-polls:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s poll did not happen", label)
		}
	}
	waitForPoll("initial")
	select {
	case interval := <-tickerReady:
		if interval != time.Minute {
			t.Fatalf("ticker interval = %s, want 1m", interval)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not create a ticker")
	}

	fake.ch <- time.Now()
	waitForPoll("ticker")
	fake.ch <- time.Now()
	waitForPoll("second ticker")

	cancel()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if !fake.stopped.Load() {
		t.Fatal("ticker was not stopped")
	}
	if batches := sink.delivered(); len(batches) != 1 {
		t.Fatalf("batches = %d, want 1: repeated feeds must be deduplicated", len(batches))
	}
}

func TestRunReturnsImmediatelyWhenCancelled(t *testing.T) {
	runner := newRunner(t, Options{
		Provider: &fakeProvider{},
		Fetcher:  &fakeFetcher{fn: nil},
		Sink:     &recordingSink{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
}
