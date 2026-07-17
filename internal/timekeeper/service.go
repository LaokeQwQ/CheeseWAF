package timekeeper

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultQueryTimeout      = 2 * time.Second
	DefaultMaxAcceptedOffset = 5 * time.Minute
	DefaultMaxRootDispersion = 2 * time.Second
	clientCancellationDrain  = 25 * time.Millisecond
)

var (
	ErrSyncInProgress       = errors.New("time synchronization already in progress")
	ErrNoUsableSource       = errors.New("no usable NTP source")
	ErrDisabled             = errors.New("time synchronization is disabled")
	ErrServiceRunning       = errors.New("time synchronization service is already running")
	ErrConfigurationChanged = errors.New("time synchronization configuration changed")
)

// Config controls source selection and synchronization cadence.
type Config struct {
	Enabled              bool
	Sources              []string
	ReselectInterval     time.Duration
	SyncInterval         time.Duration
	QueryTimeout         time.Duration
	MaxAcceptedOffset    time.Duration
	MaxRootDispersion    time.Duration
	SamplesPerSource     int
	ConsistencyThreshold time.Duration
}

// Ticker exposes a receive-only tick stream.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// TickerFactory creates monotonic interval tickers.
type TickerFactory interface {
	NewTicker(time.Duration) Ticker
}

type systemTicker struct {
	ticker *time.Ticker
}

func (t *systemTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t *systemTicker) Stop() {
	t.ticker.Stop()
}

type systemTickerFactory struct{}

func (systemTickerFactory) NewTicker(interval time.Duration) Ticker {
	return &systemTicker{ticker: time.NewTicker(interval)}
}

// DefaultConfig returns generic transport and sample safety limits.
func DefaultConfig() Config {
	return Config{
		QueryTimeout:      DefaultQueryTimeout,
		MaxAcceptedOffset: DefaultMaxAcceptedOffset,
		MaxRootDispersion: DefaultMaxRootDispersion,
	}
}

// Dependencies contains replaceable side effects used by Service.
type Dependencies struct {
	Client      Client
	Dialer      Dialer
	Clock       *DisciplinedClock
	SystemClock Clock
	Tickers     TickerFactory
}

// Status is an immutable snapshot of synchronization state.
type Status struct {
	Primary             string
	Backup              string
	ActiveSource        string
	Synchronized        bool
	Syncing             bool
	LocalFallback       bool
	Offset              time.Duration
	RTT                 time.Duration
	Stratum             uint8
	LastSuccess         time.Time
	LastAttempt         time.Time
	ConsecutiveFailures uint64
	TotalFailures       uint64
	LastError           string
}

// Service selects NTP sources and disciplines a process clock.
type Service struct {
	mu              sync.RWMutex
	config          Config
	generation      uint64
	client          Client
	ownedUDP        bool
	clock           *DisciplinedClock
	systemClock     Clock
	tickers         TickerFactory
	status          Status
	syncing         atomic.Bool
	operationMu     sync.Mutex
	operationCancel context.CancelFunc
	operationDone   chan struct{}
	reconfigureMu   sync.Mutex

	lifecycleMu   sync.Mutex
	cancel        context.CancelFunc
	done          chan struct{}
	reconfigure   chan chan struct{}
	operations    sync.WaitGroup
	scheduledMu   sync.Mutex
	scheduled     context.CancelFunc
	scheduledDone chan struct{}
}

type sourceMeasurement struct {
	source  string
	offset  time.Duration
	rtt     time.Duration
	stratum uint8
}

type syncOperation struct {
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	config     Config
	generation uint64
}

type clientQueryResult struct {
	sample Sample
	err    error
}

// NewService builds a synchronization service without starting timers.
func NewService(config Config, dependencies Dependencies) (*Service, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	systemClock := dependencies.SystemClock
	if systemClock == nil {
		systemClock = SystemClock{}
	}
	clock := dependencies.Clock
	if clock == nil {
		clock = NewDisciplinedClock(systemClock)
	}
	client := dependencies.Client
	ownedUDP := false
	if client == nil {
		udpClient := NewUDPClient()
		udpClient.Clock = systemClock
		udpClient.Timeout = normalized.QueryTimeout
		udpClient.MaxOffset = normalized.MaxAcceptedOffset
		udpClient.MaxRootDispersion = normalized.MaxRootDispersion
		if dependencies.Dialer != nil {
			udpClient.Dialer = dependencies.Dialer
		}
		client = udpClient
		ownedUDP = true
	}
	tickers := dependencies.Tickers
	if tickers == nil {
		tickers = systemTickerFactory{}
	}
	return &Service{
		config:      normalized,
		generation:  1,
		client:      client,
		ownedUDP:    ownedUDP,
		clock:       clock,
		systemClock: systemClock,
		tickers:     tickers,
		status:      Status{LocalFallback: true},
		reconfigure: make(chan chan struct{}),
	}, nil
}

// Clock returns the shared disciplined clock.
func (s *Service) Clock() Clock {
	return s.clock
}

// Status returns a read-only snapshot.
func (s *Service) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Start launches periodic selection and synchronization.
func (s *Service) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.done != nil {
		return ErrServiceRunning
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.cancel = cancel
	s.done = done
	go s.run(runCtx, done)
	return nil
}

// Stop cancels scheduled work and waits for network operations to finish.
func (s *Service) Stop() {
	s.lifecycleMu.Lock()
	cancel, done := s.cancel, s.done
	s.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.cancelActiveAndWait()
	if done != nil {
		<-done
	}
}

// Reconfigure atomically replaces runtime settings.
// Interval-only edits refresh timers without wiping a healthy selection/offset.
// Source set, enable flag, or quality-limit changes reset to local fallback.
func (s *Service) Reconfigure(config Config) error {
	s.reconfigureMu.Lock()
	defer s.reconfigureMu.Unlock()
	normalized, err := normalizeConfig(config)
	if err != nil {
		return err
	}
	s.operationMu.Lock()
	s.mu.Lock()
	previous := s.config
	materialChanged := selectionMaterialChanged(previous, normalized)
	s.config = normalized
	if materialChanged {
		s.generation++
		if s.generation == 0 {
			s.generation = 1
		}
		s.resetToLocalLocked()
	}
	activeCancel, activeDone := s.operationCancel, s.operationDone
	s.mu.Unlock()
	if materialChanged && activeCancel != nil {
		activeCancel()
	}
	s.operationMu.Unlock()
	if materialChanged && activeDone != nil {
		<-activeDone
	}

	s.lifecycleMu.Lock()
	done := s.done
	s.lifecycleMu.Unlock()
	if done == nil {
		return nil
	}
	acknowledged := make(chan struct{})
	select {
	case s.reconfigure <- acknowledged:
	case <-done:
		return nil
	}
	select {
	case <-acknowledged:
	case <-done:
	}
	return nil
}

func selectionMaterialChanged(previous, next Config) bool {
	if previous.Enabled != next.Enabled {
		return true
	}
	if !slices.Equal(previous.Sources, next.Sources) {
		return true
	}
	if previous.MaxAcceptedOffset != next.MaxAcceptedOffset ||
		previous.MaxRootDispersion != next.MaxRootDispersion ||
		previous.ConsistencyThreshold != next.ConsistencyThreshold ||
		previous.SamplesPerSource != next.SamplesPerSource ||
		previous.QueryTimeout != next.QueryTimeout {
		return true
	}
	return false
}

func (s *Service) run(ctx context.Context, done chan struct{}) {
	var reselectTicker, syncTicker Ticker
	stopTickers := func() {
		if reselectTicker != nil {
			reselectTicker.Stop()
			reselectTicker = nil
		}
		if syncTicker != nil {
			syncTicker.Stop()
			syncTicker = nil
		}
	}
	configure := func() {
		s.cancelScheduledAndWait()
		stopTickers()
		config := s.configSnapshot()
		if !config.Enabled {
			return
		}
		reselectTicker = s.tickers.NewTicker(config.ReselectInterval)
		syncTicker = s.tickers.NewTicker(config.SyncInterval)
		s.launchScheduled(ctx, s.ReselectNow)
	}
	defer func() {
		s.cancelScheduledAndWait()
		stopTickers()
		s.operations.Wait()
		s.lifecycleMu.Lock()
		if s.done == done {
			s.cancel = nil
			s.done = nil
		}
		s.lifecycleMu.Unlock()
		close(done)
	}()

	configure()
	for {
		var reselectC, syncC <-chan time.Time
		if reselectTicker != nil {
			reselectC = reselectTicker.C()
		}
		if syncTicker != nil {
			syncC = syncTicker.C()
		}
		select {
		case <-ctx.Done():
			return
		case acknowledged := <-s.reconfigure:
			configure()
			close(acknowledged)
		case <-reselectC:
			s.launchScheduled(ctx, s.ReselectNow)
		case <-syncC:
			s.launchScheduled(ctx, s.SyncNow)
		}
	}
}

func (s *Service) launchScheduled(ctx context.Context, operation func(context.Context) error) {
	s.scheduledMu.Lock()
	if s.scheduledDone != nil {
		s.scheduledMu.Unlock()
		return
	}
	operationCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.scheduled = cancel
	s.scheduledDone = done
	s.operations.Add(1)
	s.scheduledMu.Unlock()

	go func() {
		defer s.operations.Done()
		_ = operation(operationCtx)
		cancel()
		s.scheduledMu.Lock()
		if s.scheduledDone == done {
			s.scheduled = nil
			s.scheduledDone = nil
		}
		s.scheduledMu.Unlock()
		close(done)
	}()
}

func (s *Service) cancelScheduledAndWait() {
	s.scheduledMu.Lock()
	cancel, done := s.scheduled, s.scheduledDone
	s.scheduledMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// ReselectNow measures all configured sources and installs the best pair.
func (s *Service) ReselectNow(ctx context.Context) error {
	operation, ok := s.beginSync(ctx)
	if !ok {
		return ErrSyncInProgress
	}
	defer s.endSync(operation)
	ctx = operation.ctx
	s.markAttempt()
	config := operation.config
	if !config.Enabled {
		return ErrDisabled
	}

	measurements := make(chan sourceMeasurement, len(config.Sources))
	var workers sync.WaitGroup
	for _, source := range config.Sources {
		source := source
		workers.Add(1)
		go func() {
			defer workers.Done()
			if measurement, ok := s.measureSource(ctx, source, config); ok {
				measurements <- measurement
			}
		}()
	}
	workers.Wait()
	close(measurements)

	candidates := make([]sourceMeasurement, 0, len(config.Sources))
	for measurement := range measurements {
		candidates = append(candidates, measurement)
	}
	consistent := consistentMeasurements(candidates, config.ConsistencyThreshold)
	if len(consistent) == 0 {
		return s.markFailure(ErrNoUsableSource, operation.generation)
	}
	slices.SortFunc(consistent, func(a, b sourceMeasurement) int {
		if a.rtt != b.rtt {
			return compareDuration(a.rtt, b.rtt)
		}
		return strings.Compare(a.source, b.source)
	})
	primary := consistent[0]
	backup := ""
	if len(consistent) > 1 {
		backup = consistent[1].source
	}
	if !s.markSuccess(primary, primary.source, backup, operation.generation) {
		return s.operationStateError(operation.generation)
	}
	return nil
}

// SyncNow refreshes the offset from the selected primary or backup source.
// When both sources answer they must agree within ConsistencyThreshold. A lone
// responder is accepted only when its offset stays near the last agreed value
// so a single compromised host cannot step the process clock alone.
func (s *Service) SyncNow(ctx context.Context) error {
	operation, ok := s.beginSync(ctx)
	if !ok {
		return ErrSyncInProgress
	}
	defer s.endSync(operation)
	ctx = operation.ctx
	s.markAttempt()
	config := operation.config
	if !config.Enabled {
		return ErrDisabled
	}
	s.mu.RLock()
	primary, backup := s.status.Primary, s.status.Backup
	previousOffset := s.status.Offset
	previouslySynced := s.status.Synchronized
	s.mu.RUnlock()
	if primary == "" {
		return s.markFailure(ErrNoUsableSource, operation.generation)
	}

	sources := []string{primary}
	if backup != "" && backup != primary {
		sources = append(sources, backup)
	}
	queryErrors := make([]error, 0, len(sources))
	measurements := make([]sourceMeasurement, 0, len(sources))
	for _, source := range sources {
		sample, err := s.query(ctx, source, config)
		if err != nil {
			queryErrors = append(queryErrors, fmt.Errorf("query %s: %w", source, err))
			continue
		}
		measurements = append(measurements, sourceMeasurement{
			source:  source,
			offset:  sample.Offset,
			rtt:     sample.RTT,
			stratum: sample.Stratum,
		})
	}
	if len(measurements) == 0 {
		return s.markFailure(errors.Join(append([]error{ErrNoUsableSource}, queryErrors...)...), operation.generation)
	}
	chosen, err := chooseSyncMeasurement(measurements, previousOffset, previouslySynced, config.ConsistencyThreshold)
	if err != nil {
		// Keep the last disciplined offset; a disagreeing single source must not
		// wipe the clock or install a unilateral step.
		s.mu.Lock()
		if s.generation == operation.generation && s.config.Enabled {
			s.status.LastError = publicTimeSyncError(err)
			s.status.TotalFailures++
		}
		s.mu.Unlock()
		return err
	}
	if !s.markSuccess(chosen, primary, backup, operation.generation) {
		return s.operationStateError(operation.generation)
	}
	return nil
}

func chooseSyncMeasurement(measurements []sourceMeasurement, previousOffset time.Duration, previouslySynced bool, threshold time.Duration) (sourceMeasurement, error) {
	if len(measurements) == 0 {
		return sourceMeasurement{}, ErrNoUsableSource
	}
	if len(measurements) >= 2 {
		consistent := consistentMeasurements(measurements, threshold)
		if len(consistent) == 0 {
			return sourceMeasurement{}, fmt.Errorf("%w: selected NTP sources disagree", ErrNoUsableSource)
		}
		slices.SortFunc(consistent, func(a, b sourceMeasurement) int {
			if a.rtt != b.rtt {
				return compareDuration(a.rtt, b.rtt)
			}
			return strings.Compare(a.source, b.source)
		})
		return consistent[0], nil
	}
	candidate := measurements[0]
	if previouslySynced && durationDistance(candidate.offset, previousOffset) > threshold {
		return sourceMeasurement{}, fmt.Errorf("%w: sole NTP source offset jumped beyond consensus tolerance", ErrNoUsableSource)
	}
	return candidate, nil
}

func (s *Service) measureSource(ctx context.Context, source string, config Config) (sourceMeasurement, bool) {
	samples := make([]Sample, 0, config.SamplesPerSource)
	for range config.SamplesPerSource {
		if err := ctx.Err(); err != nil {
			break
		}
		sample, err := s.query(ctx, source, config)
		if err != nil {
			continue
		}
		if sample.Source == "" {
			sample.Source = source
		}
		samples = append(samples, sample)
	}
	if len(samples) < config.SamplesPerSource/2+1 {
		return sourceMeasurement{}, false
	}
	offsets := make([]time.Duration, len(samples))
	rtts := make([]time.Duration, len(samples))
	for i, sample := range samples {
		offsets[i] = sample.Offset
		rtts[i] = sample.RTT
	}
	offset := medianDuration(offsets)
	rtt := medianDuration(rtts)
	representative := samples[0]
	for _, sample := range samples[1:] {
		currentDistance := durationDistance(representative.Offset, offset)
		candidateDistance := durationDistance(sample.Offset, offset)
		if candidateDistance < currentDistance || (candidateDistance == currentDistance && sample.RTT < representative.RTT) {
			representative = sample
		}
	}
	return sourceMeasurement{source: source, offset: offset, rtt: rtt, stratum: representative.Stratum}, true
}

func (s *Service) query(ctx context.Context, source string, config Config) (Sample, error) {
	queryCtx, cancel := context.WithTimeout(ctx, config.QueryTimeout)
	defer cancel()
	client := s.client
	if s.ownedUDP {
		configured := *s.client.(*UDPClient)
		configured.Timeout = config.QueryTimeout
		configured.MaxOffset = config.MaxAcceptedOffset
		configured.MaxRootDispersion = config.MaxRootDispersion
		client = &configured
	}
	result := make(chan clientQueryResult, 1)
	go func() {
		sample, err := client.Query(queryCtx, source)
		result <- clientQueryResult{sample: sample, err: err}
	}()

	var queryResult clientQueryResult
	select {
	case <-queryCtx.Done():
		drain := time.NewTimer(clientCancellationDrain)
		select {
		case <-result:
			if !drain.Stop() {
				<-drain.C
			}
		case <-drain.C:
		}
		return Sample{}, queryCtx.Err()
	case queryResult = <-result:
		if err := queryCtx.Err(); err != nil {
			return Sample{}, err
		}
	}
	if queryResult.err != nil {
		return Sample{}, queryResult.err
	}
	sample := queryResult.sample
	if sample.Offset < -config.MaxAcceptedOffset || sample.Offset > config.MaxAcceptedOffset {
		return Sample{}, fmt.Errorf("source %s offset %v exceeds %v", source, sample.Offset, config.MaxAcceptedOffset)
	}
	if sample.RootDispersion < 0 || sample.RootDispersion > config.MaxRootDispersion {
		return Sample{}, fmt.Errorf("source %s root dispersion %v exceeds %v", source, sample.RootDispersion, config.MaxRootDispersion)
	}
	return sample, nil
}

func consistentMeasurements(measurements []sourceMeasurement, threshold time.Duration) []sourceMeasurement {
	if len(measurements) < 2 {
		return nil
	}
	sorted := slices.Clone(measurements)
	slices.SortFunc(sorted, func(a, b sourceMeasurement) int {
		if a.offset != b.offset {
			return compareDuration(a.offset, b.offset)
		}
		return strings.Compare(a.source, b.source)
	})
	bestStart, bestEnd := 0, 0
	start := 0
	for end := range sorted {
		for start < end && durationDistance(sorted[end].offset, sorted[start].offset) > threshold {
			start++
		}
		if end-start > bestEnd-bestStart || (end-start == bestEnd-bestStart && lowerRTTTotal(sorted[start:end+1], sorted[bestStart:bestEnd+1])) {
			bestStart, bestEnd = start, end
		}
	}
	if bestEnd-bestStart+1 < 2 {
		return nil
	}
	return slices.Clone(sorted[bestStart : bestEnd+1])
}

func lowerRTTTotal(candidate, current []sourceMeasurement) bool {
	var candidateTotal, currentTotal time.Duration
	for _, measurement := range candidate {
		candidateTotal += measurement.rtt
	}
	for _, measurement := range current {
		currentTotal += measurement.rtt
	}
	return candidateTotal < currentTotal
}

func medianDuration(values []time.Duration) time.Duration {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return sorted[middle-1] + (sorted[middle]-sorted[middle-1])/2
}

func durationDistance(a, b time.Duration) time.Duration {
	if a >= b {
		return a - b
	}
	return b - a
}

func compareDuration(a, b time.Duration) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func (s *Service) beginSync(ctx context.Context) (*syncOperation, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if !s.syncing.CompareAndSwap(false, true) {
		return nil, false
	}
	operationCtx, cancel := context.WithCancel(ctx)
	operation := &syncOperation{
		ctx:    operationCtx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	s.mu.Lock()
	operation.config = s.config
	operation.config.Sources = slices.Clone(s.config.Sources)
	operation.generation = s.generation
	s.status.Syncing = true
	s.mu.Unlock()
	s.operationCancel = cancel
	s.operationDone = operation.done
	return operation, true
}

func (s *Service) endSync(operation *syncOperation) {
	operation.cancel()
	s.operationMu.Lock()
	s.mu.Lock()
	s.status.Syncing = false
	s.mu.Unlock()
	if s.operationDone == operation.done {
		s.operationCancel = nil
		s.operationDone = nil
	}
	s.syncing.Store(false)
	close(operation.done)
	s.operationMu.Unlock()
}

func (s *Service) cancelActiveAndWait() {
	s.operationMu.Lock()
	cancel, done := s.operationCancel, s.operationDone
	if cancel != nil {
		cancel()
	}
	s.operationMu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *Service) markAttempt() {
	s.mu.Lock()
	s.status.LastAttempt = s.systemClock.Now()
	s.mu.Unlock()
}

func (s *Service) markSuccess(measurement sourceMeasurement, primary, backup string, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.config.Enabled || s.generation != generation {
		return false
	}
	s.clock.SetOffset(measurement.offset)
	s.status.Primary = primary
	s.status.Backup = backup
	s.status.ActiveSource = measurement.source
	s.status.Synchronized = true
	s.status.LocalFallback = false
	s.status.Offset = measurement.offset
	s.status.RTT = measurement.rtt
	s.status.Stratum = measurement.stratum
	s.status.LastSuccess = s.systemClock.Now()
	s.status.ConsecutiveFailures = 0
	s.status.LastError = ""
	return true
}

func (s *Service) markFailure(err error, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != generation {
		return ErrConfigurationChanged
	}
	if !s.config.Enabled {
		return ErrDisabled
	}
	s.clock.SetOffset(0)
	s.status.ActiveSource = ""
	s.status.Synchronized = false
	s.status.LocalFallback = true
	s.status.Offset = 0
	s.status.RTT = 0
	s.status.Stratum = 0
	s.status.ConsecutiveFailures++
	s.status.TotalFailures++
	s.status.LastError = publicTimeSyncError(err)
	return err
}

func publicTimeSyncError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoUsableSource):
		return "no usable NTP source"
	case errors.Is(err, ErrDisabled):
		return "time synchronization is disabled"
	case errors.Is(err, ErrConfigurationChanged):
		return "time synchronization configuration changed"
	case errors.Is(err, ErrSyncInProgress):
		return "time synchronization already in progress"
	case errors.Is(err, context.DeadlineExceeded):
		return "time synchronization timed out"
	case errors.Is(err, context.Canceled):
		return "time synchronization canceled"
	default:
		return "time synchronization failed"
	}
}

func (s *Service) operationStateError(generation uint64) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.generation != generation {
		return ErrConfigurationChanged
	}
	if !s.config.Enabled {
		return ErrDisabled
	}
	return ErrConfigurationChanged
}

func (s *Service) resetToLocalLocked() {
	// Drop the clamp so local fallback immediately tracks the system clock.
	s.clock.ResetToSource()
	s.status.Primary = ""
	s.status.Backup = ""
	s.status.ActiveSource = ""
	s.status.Synchronized = false
	s.status.LocalFallback = true
	s.status.Offset = 0
	s.status.RTT = 0
	s.status.Stratum = 0
	s.status.LastError = ""
}

func (s *Service) configSnapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	config := s.config
	config.Sources = slices.Clone(config.Sources)
	return config
}

func normalizeConfig(config Config) (Config, error) {
	defaults := DefaultConfig()
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaults.QueryTimeout
	}
	if config.MaxAcceptedOffset == 0 {
		config.MaxAcceptedOffset = defaults.MaxAcceptedOffset
	}
	if config.MaxRootDispersion == 0 {
		config.MaxRootDispersion = defaults.MaxRootDispersion
	}
	if config.ReselectInterval < 0 || config.SyncInterval < 0 || config.QueryTimeout < 0 || config.MaxAcceptedOffset < 0 || config.MaxRootDispersion < 0 || config.SamplesPerSource < 0 || config.ConsistencyThreshold < 0 {
		return Config{}, fmt.Errorf("invalid timekeeper configuration")
	}
	seen := make(map[string]struct{}, len(config.Sources))
	sources := make([]string, 0, len(config.Sources))
	for _, source := range config.Sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if _, exists := seen[source]; exists {
			continue
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	config.Sources = sources
	if config.Enabled {
		if len(config.Sources) == 0 {
			return Config{}, errors.New("at least one NTP source is required")
		}
		if config.ReselectInterval <= 0 || config.SyncInterval <= 0 {
			return Config{}, errors.New("NTP reselect and sync intervals are required")
		}
		if config.SamplesPerSource < 1 || config.ConsistencyThreshold <= 0 {
			return Config{}, errors.New("NTP sampling and consistency settings are required")
		}
	}
	return config, nil
}
