package timekeeper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type queryResult struct {
	sample Sample
	err    error
}

type fakeClient struct {
	mu        sync.Mutex
	results   map[string][]queryResult
	calls     []string
	deadlines []time.Time
	active    int
	maxSeen   int
	block     <-chan struct{}
	entered   chan string
}

type fakeTicker struct {
	mu        sync.Mutex
	ch        chan time.Time
	stopCount int
}

func (t *fakeTicker) C() <-chan time.Time {
	return t.ch
}

func (t *fakeTicker) Stop() {
	t.mu.Lock()
	t.stopCount++
	t.mu.Unlock()
}

func (t *fakeTicker) Stopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopCount > 0
}

type fakeTickerFactory struct {
	mu        sync.Mutex
	tickers   []*fakeTicker
	durations []time.Duration
}

type ignoringClient struct {
	mu      sync.Mutex
	entered chan string
	release chan struct{}
	active  int
	offset  time.Duration
}

func (c *ignoringClient) Query(_ context.Context, source string) (Sample, error) {
	c.mu.Lock()
	c.active++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
	}()
	if c.entered != nil {
		c.entered <- source
	}
	<-c.release
	return Sample{Source: source, Offset: c.offset, RTT: time.Millisecond, Stratum: 2}, nil
}

func (c *ignoringClient) Active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

type lateSuccessClient struct{}

func (lateSuccessClient) Query(ctx context.Context, source string) (Sample, error) {
	<-ctx.Done()
	return Sample{Source: source, Offset: time.Millisecond, RTT: time.Millisecond, Stratum: 2}, nil
}

type initialThenIgnoringClient struct {
	mu      sync.Mutex
	calls   map[string]int
	entered chan string
	release chan struct{}
	active  int
}

func (c *initialThenIgnoringClient) Query(_ context.Context, source string) (Sample, error) {
	c.mu.Lock()
	c.calls[source]++
	call := c.calls[source]
	if call > 1 {
		c.active++
	}
	c.mu.Unlock()
	if call == 1 {
		rtt := 10 * time.Millisecond
		if source == "old-b" {
			rtt = 20 * time.Millisecond
		}
		return Sample{Source: source, Offset: 10 * time.Millisecond, RTT: rtt, Stratum: 2}, nil
	}
	defer func() {
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
	}()
	c.entered <- source
	<-c.release
	return Sample{Source: source, Offset: 20 * time.Millisecond, RTT: time.Millisecond, Stratum: 2}, nil
}

func (c *initialThenIgnoringClient) Active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (f *fakeTickerFactory) NewTicker(interval time.Duration) Ticker {
	ticker := &fakeTicker{ch: make(chan time.Time, 1)}
	f.mu.Lock()
	f.tickers = append(f.tickers, ticker)
	f.durations = append(f.durations, interval)
	f.mu.Unlock()
	return ticker
}

func (f *fakeTickerFactory) Snapshot() ([]*fakeTicker, []time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeTicker(nil), f.tickers...), append([]time.Duration(nil), f.durations...)
}

func (c *fakeClient) Query(ctx context.Context, source string) (Sample, error) {
	c.mu.Lock()
	c.calls = append(c.calls, source)
	if deadline, ok := ctx.Deadline(); ok {
		c.deadlines = append(c.deadlines, deadline)
	}
	c.active++
	if c.active > c.maxSeen {
		c.maxSeen = c.active
	}
	c.mu.Unlock()
	if c.entered != nil {
		select {
		case c.entered <- source:
		case <-ctx.Done():
			return Sample{}, ctx.Err()
		}
	}
	defer func() {
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
	}()

	if c.block != nil {
		select {
		case <-ctx.Done():
			return Sample{}, ctx.Err()
		case <-c.block:
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	results := c.results[source]
	if len(results) == 0 {
		return Sample{}, errors.New("no scripted result")
	}
	result := results[0]
	c.results[source] = results[1:]
	return result.sample, result.err
}

func samples(source string, rtts []time.Duration, offsets []time.Duration, stratum uint8) []queryResult {
	results := make([]queryResult, len(rtts))
	for i := range rtts {
		results[i].sample = Sample{
			Source:  source,
			RTT:     rtts[i],
			Offset:  offsets[i],
			Stratum: stratum,
		}
	}
	return results
}

func TestDefaultConfigOnlyIncludesGenericSafetyLimits(t *testing.T) {
	config := DefaultConfig()
	if config.Enabled {
		t.Fatal("generic defaults enabled the service")
	}
	if len(config.Sources) != 0 || config.ReselectInterval != 0 || config.SyncInterval != 0 {
		t.Fatalf("generic defaults contain product sources or cadence: %+v", config)
	}
	if config.SamplesPerSource != 0 || config.ConsistencyThreshold != 0 {
		t.Fatalf("generic defaults contain product sampling policy: %+v", config)
	}
	if config.QueryTimeout != 2*time.Second {
		t.Fatalf("default query timeout = %v, want 2s", config.QueryTimeout)
	}
	if config.MaxAcceptedOffset != 5*time.Minute {
		t.Fatalf("default max accepted offset = %v, want 5m", config.MaxAcceptedOffset)
	}
	if config.MaxRootDispersion != 2*time.Second {
		t.Fatalf("default max root dispersion = %v, want 2s", config.MaxRootDispersion)
	}

}

func TestNewServiceConfiguresDefaultUDPClient(t *testing.T) {
	raw := &fakeClock{now: time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)}
	dialer := &fakeDialer{}
	config := DefaultConfig()
	config.QueryTimeout = 7 * time.Second
	config.MaxAcceptedOffset = 3 * time.Hour
	config.MaxRootDispersion = 4 * time.Second

	service, err := NewService(config, Dependencies{SystemClock: raw, Dialer: dialer})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	client, ok := service.client.(*UDPClient)
	if !ok {
		t.Fatalf("default client type = %T, want *UDPClient", service.client)
	}
	if client.Clock != raw || client.Dialer != dialer {
		t.Fatalf("default client dependencies = %T/%T, want injected clock/dialer", client.Clock, client.Dialer)
	}
	if client.Timeout != config.QueryTimeout || client.MaxOffset != config.MaxAcceptedOffset || client.MaxRootDispersion != config.MaxRootDispersion {
		t.Fatalf("default client limits = %v/%v/%v, want %v/%v/%v", client.Timeout, client.MaxOffset, client.MaxRootDispersion, config.QueryTimeout, config.MaxAcceptedOffset, config.MaxRootDispersion)
	}
}

func TestServiceReselectsConsistentLowestLatencySources(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"fast": samples(
			"fast",
			[]time.Duration{10 * time.Millisecond, 15 * time.Millisecond, 12 * time.Millisecond},
			[]time.Duration{20 * time.Millisecond, 25 * time.Millisecond, 22 * time.Millisecond},
			2,
		),
		"backup": samples(
			"backup",
			[]time.Duration{20 * time.Millisecond, 25 * time.Millisecond, 22 * time.Millisecond},
			[]time.Duration{24 * time.Millisecond, 26 * time.Millisecond, 25 * time.Millisecond},
			3,
		),
		"outlier": samples(
			"outlier",
			[]time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond},
			[]time.Duration{5 * time.Second, 5100 * time.Millisecond, 4900 * time.Millisecond},
			1,
		),
	}}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"fast", "backup", "outlier"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     3,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{
		Client:      client,
		Clock:       disciplined,
		SystemClock: raw,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}

	status := service.Status()
	if status.Primary != "fast" || status.Backup != "backup" {
		t.Fatalf("selected primary/backup = %q/%q, want fast/backup", status.Primary, status.Backup)
	}
	if status.ActiveSource != "fast" {
		t.Fatalf("active source = %q, want fast", status.ActiveSource)
	}
	if status.Offset != 22*time.Millisecond || disciplined.Offset() != 22*time.Millisecond {
		t.Fatalf("selected offset/status = %v/%v, want 22ms", disciplined.Offset(), status.Offset)
	}
	if status.RTT != 12*time.Millisecond || status.Stratum != 2 {
		t.Fatalf("selected RTT/stratum = %v/%d, want 12ms/2", status.RTT, status.Stratum)
	}
	if !status.Synchronized || status.LocalFallback {
		t.Fatalf("unexpected synchronization state: %+v", status)
	}
	if !status.LastAttempt.Equal(now) || !status.LastSuccess.Equal(now) {
		t.Fatalf("attempt/success = %v/%v, want %v", status.LastAttempt, status.LastSuccess, now)
	}
}

func TestServiceSyncFallsBackToBackup(t *testing.T) {
	initialTime := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: initialTime}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"primary": {
			{sample: Sample{Source: "primary", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
			{err: errors.New("primary unavailable")},
		},
		"backup": {
			{sample: Sample{Source: "backup", Offset: 12 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
			{sample: Sample{Source: "backup", Offset: 31 * time.Millisecond, RTT: 14 * time.Millisecond, Stratum: 3}},
		},
	}}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"primary", "backup"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}

	syncTime := initialTime.Add(time.Hour)
	raw.Set(syncTime)
	if err := service.SyncNow(context.Background()); err != nil {
		t.Fatalf("SyncNow() error = %v", err)
	}

	status := service.Status()
	if status.Primary != "primary" || status.Backup != "backup" {
		t.Fatalf("primary/backup changed to %q/%q", status.Primary, status.Backup)
	}
	if status.ActiveSource != "backup" {
		t.Fatalf("active source = %q, want backup", status.ActiveSource)
	}
	if status.Offset != 31*time.Millisecond || disciplined.Offset() != 31*time.Millisecond {
		t.Fatalf("backup offset/status = %v/%v, want 31ms", disciplined.Offset(), status.Offset)
	}
	if status.RTT != 14*time.Millisecond || status.Stratum != 3 {
		t.Fatalf("backup RTT/stratum = %v/%d, want 14ms/3", status.RTT, status.Stratum)
	}
	if !status.LastAttempt.Equal(syncTime) || !status.LastSuccess.Equal(syncTime) {
		t.Fatalf("attempt/success = %v/%v, want %v", status.LastAttempt, status.LastSuccess, syncTime)
	}
	if status.ConsecutiveFailures != 0 || status.TotalFailures != 0 || status.LocalFallback {
		t.Fatalf("unexpected failure status after backup success: %+v", status)
	}
}

func TestServiceSyncRejectsUnilateralOffsetJump(t *testing.T) {
	initialTime := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: initialTime}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"primary": {
			{sample: Sample{Source: "primary", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
			{sample: Sample{Source: "primary", Offset: 2 * time.Second, RTT: 5 * time.Millisecond, Stratum: 2}},
		},
		"backup": {
			{sample: Sample{Source: "backup", Offset: 12 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
			{err: errors.New("backup unavailable")},
		},
	}}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"primary", "backup"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}
	if disciplined.Offset() != 10*time.Millisecond {
		t.Fatalf("pre-sync offset = %v, want 10ms", disciplined.Offset())
	}

	err = service.SyncNow(context.Background())
	if !errors.Is(err, ErrNoUsableSource) {
		t.Fatalf("SyncNow() error = %v, want ErrNoUsableSource", err)
	}
	if disciplined.Offset() != 10*time.Millisecond {
		t.Fatalf("unilateral jump overwrote offset: %v", disciplined.Offset())
	}
	status := service.Status()
	if !status.Synchronized || status.LocalFallback || status.Offset != 10*time.Millisecond {
		t.Fatalf("healthy selection should be preserved after rejected jump: %+v", status)
	}
}

func TestServiceReconfigureIntervalOnlyKeepsSelection(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"a": {{sample: Sample{Source: "a", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}}},
		"b": {{sample: Sample{Source: "b", Offset: 12 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}}},
	}}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}
	if err := service.Reconfigure(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     3 * time.Hour,
		SyncInterval:         90 * time.Minute,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
	status := service.Status()
	if !status.Synchronized || status.Primary != "a" || status.Backup != "b" || status.Offset != 10*time.Millisecond {
		t.Fatalf("interval-only reconfigure wiped selection: %+v", status)
	}
	if disciplined.Offset() != 10*time.Millisecond {
		t.Fatalf("interval-only reconfigure wiped offset: %v", disciplined.Offset())
	}
}

func TestServiceEnforcesQueryQualityConfiguration(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"good-a":         {{sample: Sample{Source: "good-a", Offset: 10 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 2, RootDispersion: 10 * time.Millisecond}}},
		"good-b":         {{sample: Sample{Source: "good-b", Offset: 12 * time.Millisecond, RTT: 20 * time.Millisecond, Stratum: 3, RootDispersion: 20 * time.Millisecond}}},
		"bad-offset":     {{sample: Sample{Source: "bad-offset", Offset: 2 * time.Hour, RTT: time.Millisecond, Stratum: 1, RootDispersion: time.Millisecond}}},
		"bad-dispersion": {{sample: Sample{Source: "bad-dispersion", Offset: 11 * time.Millisecond, RTT: 2 * time.Millisecond, Stratum: 1, RootDispersion: 2 * time.Second}}},
	}}
	queryTimeout := 5 * time.Second
	before := time.Now()
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"good-a", "good-b", "bad-offset", "bad-dispersion"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
		QueryTimeout:         queryTimeout,
		MaxAcceptedOffset:    time.Hour,
		MaxRootDispersion:    time.Second,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}
	after := time.Now()

	status := service.Status()
	if status.Primary != "good-a" || status.Backup != "good-b" {
		t.Fatalf("selected primary/backup = %q/%q, want good-a/good-b", status.Primary, status.Backup)
	}
	client.mu.Lock()
	deadlines := append([]time.Time(nil), client.deadlines...)
	client.mu.Unlock()
	if len(deadlines) != 4 {
		t.Fatalf("query contexts with deadlines = %d, want 4", len(deadlines))
	}
	for _, deadline := range deadlines {
		if deadline.Before(before.Add(queryTimeout)) || deadline.After(after.Add(queryTimeout)) {
			t.Errorf("query deadline %v is outside [%v, %v]", deadline, before.Add(queryTimeout), after.Add(queryTimeout))
		}
	}
}

func TestServiceRequiresTwoConsistentSourcesForInitialSelection(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"only": {{sample: Sample{Source: "only", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}}},
	}}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"only"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	err = service.ReselectNow(context.Background())
	if !errors.Is(err, ErrNoUsableSource) {
		t.Fatalf("ReselectNow() error = %v, want ErrNoUsableSource", err)
	}
	status := service.Status()
	if status.Synchronized || !status.LocalFallback || status.Primary != "" || status.Backup != "" {
		t.Fatalf("single source established synchronization: %+v", status)
	}
	if status.ConsecutiveFailures != 1 || status.TotalFailures != 1 {
		t.Fatalf("failure counters = %d/%d, want 1/1", status.ConsecutiveFailures, status.TotalFailures)
	}
	if disciplined.Offset() != 0 {
		t.Fatalf("disciplined offset = %v, want local zero offset", disciplined.Offset())
	}
}

func TestServiceAllSourcesFailFallsBackWithoutMovingTimeBackward(t *testing.T) {
	initialTime := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: initialTime}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"primary": {
			{sample: Sample{Source: "primary", Offset: 10 * time.Second, RTT: 5 * time.Millisecond, Stratum: 2}},
			{err: errors.New("primary failed")},
		},
		"backup": {
			{sample: Sample{Source: "backup", Offset: 10005 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
			{err: errors.New("backup failed")},
		},
	}}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"primary", "backup"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}
	beforeFailure := disciplined.Now()

	raw.Set(initialTime.Add(time.Second))
	err = service.SyncNow(context.Background())
	if !errors.Is(err, ErrNoUsableSource) {
		t.Fatalf("SyncNow() error = %v, want ErrNoUsableSource", err)
	}
	afterFailure := disciplined.Now()
	if afterFailure.Before(beforeFailure) {
		t.Fatalf("fallback moved time backward from %v to %v", beforeFailure, afterFailure)
	}

	status := service.Status()
	if status.Synchronized || !status.LocalFallback || status.ActiveSource != "" {
		t.Fatalf("unexpected fallback status: %+v", status)
	}
	if status.Offset != 0 || disciplined.Offset() != 0 {
		t.Fatalf("fallback offset/status = %v/%v, want zero", disciplined.Offset(), status.Offset)
	}
	if status.ConsecutiveFailures != 1 || status.TotalFailures != 1 {
		t.Fatalf("failure counters = %d/%d, want 1/1", status.ConsecutiveFailures, status.TotalFailures)
	}
}

func TestServicePreventsSynchronizationReentry(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	block := make(chan struct{})
	entered := make(chan string, 2)
	client := &fakeClient{
		block:   block,
		entered: entered,
		results: map[string][]queryResult{
			"a": {{sample: Sample{Source: "a", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}}},
			"b": {{sample: Sample{Source: "b", Offset: 12 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}}},
		},
	}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, SystemClock: raw})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- service.ReselectNow(context.Background())
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for initial queries")
		}
	}
	if !service.Status().Syncing {
		t.Fatal("status did not report synchronization in progress")
	}
	if err := service.SyncNow(context.Background()); !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("concurrent SyncNow() error = %v, want ErrSyncInProgress", err)
	}
	client.mu.Lock()
	callCount := len(client.calls)
	client.mu.Unlock()
	if callCount != 2 {
		t.Fatalf("client calls after rejected reentry = %d, want 2", callCount)
	}

	close(block)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("initial ReselectNow() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial reselect")
	}
	if service.Status().Syncing {
		t.Fatal("status remained syncing after completion")
	}
}

func TestServiceReconfigureDisablesAndReenablesWithoutTickerLeaks(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	disciplined := NewDisciplinedClock(raw)
	client := &fakeClient{results: map[string][]queryResult{
		"a": {
			{sample: Sample{Source: "a", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
			{sample: Sample{Source: "a", Offset: 20 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
		},
		"b": {
			{sample: Sample{Source: "b", Offset: 12 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
			{sample: Sample{Source: "b", Offset: 22 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
		},
	}}
	tickers := &fakeTickerFactory{}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, Clock: disciplined, SystemClock: raw, Tickers: tickers})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(service.Stop)
	waitFor(t, time.Second, func() bool {
		return service.Status().Synchronized
	})
	initialTickers, initialDurations := tickers.Snapshot()
	if len(initialTickers) != 2 {
		t.Fatalf("initial ticker count = %d, want 2", len(initialTickers))
	}
	if initialDurations[0] != 2*time.Hour || initialDurations[1] != time.Hour {
		t.Fatalf("initial ticker durations = %v, want [2h 1h]", initialDurations)
	}

	if err := service.Reconfigure(Config{
		Enabled:              false,
		Sources:              []string{"a", "b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}); err != nil {
		t.Fatalf("disable Reconfigure() error = %v", err)
	}
	status := service.Status()
	if status.Synchronized || !status.LocalFallback || status.Offset != 0 || disciplined.Offset() != 0 {
		t.Fatalf("disabled status/offset = %+v/%v", status, disciplined.Offset())
	}
	for i, ticker := range initialTickers {
		if !ticker.Stopped() {
			t.Errorf("initial ticker %d was not stopped", i)
		}
	}
	if got, _ := tickers.Snapshot(); len(got) != 2 {
		t.Fatalf("disabled service created tickers: count = %d", len(got))
	}

	raw.Set(now.Add(time.Minute))
	if err := service.Reconfigure(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     4 * time.Hour,
		SyncInterval:         2 * time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}); err != nil {
		t.Fatalf("enable Reconfigure() error = %v", err)
	}
	waitFor(t, time.Second, func() bool {
		status := service.Status()
		return status.Synchronized && status.Offset == 20*time.Millisecond
	})
	allTickers, durations := tickers.Snapshot()
	if len(allTickers) != 4 {
		t.Fatalf("ticker count after re-enable = %d, want 4", len(allTickers))
	}
	if durations[2] != 4*time.Hour || durations[3] != 2*time.Hour {
		t.Fatalf("re-enabled ticker durations = %v, want suffix [4h 2h]", durations)
	}

	service.Stop()
	for i, ticker := range allTickers {
		if !ticker.Stopped() {
			t.Errorf("ticker %d leaked after Stop", i)
		}
	}
}

func TestServiceStopCancelsImmediateReselection(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	block := make(chan struct{})
	entered := make(chan string, 2)
	client := &fakeClient{
		block:   block,
		entered: entered,
		results: map[string][]queryResult{
			"a": {{sample: Sample{Source: "a"}}},
			"b": {{sample: Sample{Source: "b"}}},
		},
	}
	tickers := &fakeTickerFactory{}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, SystemClock: raw, Tickers: tickers})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for immediate reselection queries")
		}
	}

	stopped := make(chan struct{})
	go func() {
		service.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel the active reselection")
	}
	client.mu.Lock()
	active := client.active
	client.mu.Unlock()
	if active != 0 {
		t.Fatalf("active client queries after Stop = %d, want 0", active)
	}
	created, _ := tickers.Snapshot()
	if len(created) != 2 {
		t.Fatalf("created ticker count = %d, want 2", len(created))
	}
	for i, ticker := range created {
		if !ticker.Stopped() {
			t.Errorf("ticker %d leaked after cancellation", i)
		}
	}
}

func TestServiceTickerEventsTriggerSyncAndReselection(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	raw := &fakeClock{now: now}
	// SyncNow queries primary and backup together, so each periodic step must
	// supply samples for both selected sources.
	client := &fakeClient{results: map[string][]queryResult{
		"a": {
			{sample: Sample{Source: "a", Offset: 10 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
			{sample: Sample{Source: "a", Offset: 20 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
			{sample: Sample{Source: "a", Offset: 30 * time.Millisecond, RTT: 5 * time.Millisecond, Stratum: 2}},
		},
		"b": {
			{sample: Sample{Source: "b", Offset: 12 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
			{sample: Sample{Source: "b", Offset: 22 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
			{sample: Sample{Source: "b", Offset: 32 * time.Millisecond, RTT: 10 * time.Millisecond, Stratum: 3}},
		},
	}}
	tickers := &fakeTickerFactory{}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"a", "b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client, SystemClock: raw, Tickers: tickers})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(service.Stop)
	waitFor(t, time.Second, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return service.Status().Offset == 10*time.Millisecond && client.active == 0
	})
	created, _ := tickers.Snapshot()
	if len(created) != 2 {
		t.Fatalf("created ticker count = %d, want 2", len(created))
	}

	raw.Set(now.Add(time.Minute))
	created[1].ch <- raw.Now()
	waitFor(t, time.Second, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return service.Status().Offset == 20*time.Millisecond && client.active == 0
	})

	raw.Set(now.Add(2 * time.Minute))
	created[0].ch <- raw.Now()
	waitFor(t, time.Second, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return service.Status().Offset == 30*time.Millisecond && client.active == 0
	})
	status := service.Status()
	if status.Primary != "a" || status.Backup != "b" || !status.LastAttempt.Equal(raw.Now()) {
		t.Fatalf("unexpected status after ticker events: %+v", status)
	}
}

func TestServiceReconfigureInvalidatesExternalReselection(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseClient := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseClient)
	client := &ignoringClient{
		entered: make(chan string, 2),
		release: release,
		offset:  10 * time.Millisecond,
	}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"old-a", "old-b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	oldDone := make(chan error, 1)
	go func() { oldDone <- service.ReselectNow(context.Background()) }()
	for range 2 {
		select {
		case <-client.entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for old-config queries")
		}
	}
	if err := service.Reconfigure(Config{
		Enabled:              true,
		Sources:              []string{"new-a", "new-b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         time.Second,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
	select {
	case err := <-oldDone:
		if !errors.Is(err, ErrConfigurationChanged) {
			t.Fatalf("old ReselectNow() error = %v, want ErrConfigurationChanged", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Reconfigure did not close the external reselection")
	}
	status := service.Status()
	if status.Primary == "old-a" || status.Primary == "old-b" || status.Synchronized {
		t.Fatalf("old configuration wrote synchronization state: %+v", status)
	}

	releaseClient()
	waitFor(t, time.Second, func() bool { return client.Active() == 0 })
	status = service.Status()
	if status.Primary == "old-a" || status.Primary == "old-b" {
		t.Fatalf("late old result wrote primary source: %+v", status)
	}
}

func TestServiceReconfigureInvalidatesExternalSync(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseClient := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseClient)
	client := &initialThenIgnoringClient{
		calls:   make(map[string]int),
		entered: make(chan string, 1),
		release: release,
	}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"old-a", "old-b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.ReselectNow(context.Background()); err != nil {
		t.Fatalf("ReselectNow() error = %v", err)
	}

	syncDone := make(chan error, 1)
	go func() { syncDone <- service.SyncNow(context.Background()) }()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for old-config sync")
	}
	if err := service.Reconfigure(Config{
		Enabled:              true,
		Sources:              []string{"new-a", "new-b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         time.Second,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
	select {
	case err := <-syncDone:
		if !errors.Is(err, ErrConfigurationChanged) {
			t.Fatalf("old SyncNow() error = %v, want ErrConfigurationChanged", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Reconfigure did not close the external sync")
	}
	if status := service.Status(); status.Synchronized || status.Primary != "" || status.Backup != "" {
		t.Fatalf("old sync state survived reconfiguration: %+v", status)
	}

	releaseClient()
	waitFor(t, time.Second, func() bool { return client.Active() == 0 })
	if status := service.Status(); status.Synchronized || status.ActiveSource != "" {
		t.Fatalf("late old sync result restored synchronization: %+v", status)
	}
}

func TestServiceRejectsSuccessfulSampleReturnedAfterTimeout(t *testing.T) {
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"late-a", "late-b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         20 * time.Millisecond,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: lateSuccessClient{}})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	err = service.ReselectNow(context.Background())
	if !errors.Is(err, ErrNoUsableSource) {
		t.Fatalf("ReselectNow() error = %v, want ErrNoUsableSource", err)
	}
	if status := service.Status(); status.Synchronized || !status.LocalFallback {
		t.Fatalf("late successful samples established synchronization: %+v", status)
	}
}

func TestServiceStopClosesLifecycleWhenClientIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseClient := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseClient)
	client := &ignoringClient{
		entered: make(chan string, 2),
		release: release,
	}
	service, err := NewService(Config{
		Enabled:              true,
		Sources:              []string{"blocked-a", "blocked-b"},
		ReselectInterval:     2 * time.Hour,
		SyncInterval:         time.Hour,
		QueryTimeout:         time.Hour,
		SamplesPerSource:     1,
		ConsistencyThreshold: 50 * time.Millisecond,
	}, Dependencies{Client: client})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	for range 2 {
		select {
		case <-client.entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for blocked queries")
		}
	}

	stopped := make(chan struct{})
	go func() {
		service.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop waited for a Client that ignored context cancellation")
	}

	releaseClient()
	waitFor(t, time.Second, func() bool { return client.Active() == 0 })
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}
