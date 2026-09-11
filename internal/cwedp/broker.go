package cwedp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrJobNotFound          = errors.New("distribution job not found")
	ErrBrokerQueue          = errors.New("distribution broker queue is full")
	ErrJobConflict          = errors.New("distribution job conflicts with existing intent")
	ErrTransferTooLarge     = errors.New("distribution artifact exceeds broker byte budget")
	ErrResumeOffsetConflict = errors.New("distribution resume offset conflict")
	ErrAtomicResumeRequired = errors.New("distribution broker requires atomic resume persistence")
	ErrJobTerminal          = errors.New("distribution job is terminal")
)

// LeaseBinding is the minimum context a runtime broker must bind before a
// plugin is allowed to participate in a distribution transfer.
type LeaseBinding struct {
	PluginID, PluginVersion string
	TargetHost              string
	TargetPort              int
	TargetProtocol          string
	TLSFingerprint          string
	PolicyEpoch             uint64
	ConfirmationID          string
}

// LeaseVerifier is deliberately an interface so the broker can be wired to
// netlease.Manager without opening sockets in this package.
type LeaseVerifier interface {
	VerifyLease(LeaseBinding) error
}

// ResumeState is the durable boundary for a resumable transfer. A production
// implementation should persist this record transactionally; the in-memory
// implementation below is only a deterministic contract test adapter.
type ResumeState struct {
	JobID      string
	Intent     DistributionIntent
	Source     Source
	MaxChunk   int64
	NextOffset int64
	Data       []byte
	Complete   bool
	Failed     bool
	Failure    string
	// QuarantinedSources is append-only. Once a source reports an integrity,
	// transport or policy failure it cannot be selected again for this intent.
	QuarantinedSources []SourceQuarantine
	SourceSwitches     int
	MaxSourceSwitches  int
	UpdatedAt          time.Time
}

type ResumeStore interface {
	Save(context.Context, ResumeState) error
	Load(context.Context, string) (ResumeState, error)
}

// AtomicResumeStore is required by Broker because a load/modify/save cycle
// without compare-and-swap can duplicate chunks when two workers race.
type AtomicResumeStore interface {
	ResumeStore
	SaveExpected(context.Context, int64, ResumeState) error
}

type MemoryResumeStore struct {
	mu   sync.Mutex
	data map[string]ResumeState
}

func NewMemoryResumeStore() *MemoryResumeStore {
	return &MemoryResumeStore{data: make(map[string]ResumeState)}
}

func (s *MemoryResumeStore) Save(_ context.Context, state ResumeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state.JobID] = cloneResumeState(state)
	return nil
}

// SaveExpected atomically applies a loaded state when the offset is unchanged.
func (s *MemoryResumeStore) SaveExpected(ctx context.Context, expectedOffset int64, state ResumeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, ok := s.data[state.JobID]
	if !ok {
		if expectedOffset != 0 {
			return ErrResumeOffsetConflict
		}
	} else if current.NextOffset != expectedOffset {
		return ErrResumeOffsetConflict
	} else if current.Intent.Validate() == nil && state.Intent.Validate() == nil && int64(len(current.Data)) == current.NextOffset && int64(len(state.Data)) == state.NextOffset {
		// Keep the in-memory adapter's CAS semantics close to the PostgreSQL
		// adapter. Corrupt-state tests intentionally bypass this guard through
		// Save, while normal duplicate submits and source switches must not
		// overwrite a concurrent writer.
		if err := ValidateResumeTransition(current, state); err != nil {
			return err
		}
	}
	s.data[state.JobID] = cloneResumeState(state)
	return nil
}

func (s *MemoryResumeStore) Load(_ context.Context, id string) (ResumeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.data[id]
	if !ok {
		return ResumeState{}, ErrJobNotFound
	}
	return cloneResumeState(state), nil
}

func cloneResumeState(state ResumeState) ResumeState {
	state.Data = append([]byte(nil), state.Data...)
	state.Intent.Sources = append([]Source(nil), state.Intent.Sources...)
	state.QuarantinedSources = append([]SourceQuarantine(nil), state.QuarantinedSources...)
	return state
}

type BrokerConfig struct {
	Registry          SourceRegistry
	ResumeStore       ResumeStore
	LeaseVerifier     LeaseVerifier
	QueueSize         int
	MaxChunkBytes     int64
	MaxArtifactBytes  int64
	MaxSourceSwitches int
	// MinIndependentSources defaults to two. A trusted low-risk/observe
	// deployment may explicitly set one; values above two are not accepted.
	MinIndependentSources int
}

type TransferRequest struct {
	Intent       DistributionIntent
	Hello        Hello
	Capabilities Capabilities
	Lease        LeaseBinding
}

type Job struct {
	ID         string
	Source     Source
	NextOffset int64
}

type TransferResult struct {
	JobID             string
	NextOffset        int64
	Complete          bool
	Failed            bool
	Failure           error
	Retrying          bool
	Source            Source
	QuarantinedSource Source
}

type chunkRequest struct {
	id     string
	offset int64
	data   []byte
}

type Broker struct {
	registry              SourceRegistry
	store                 ResumeStore
	verifier              LeaseVerifier
	queue                 chan chunkRequest
	maxChunkBytes         int64
	maxArtifactBytes      int64
	maxSourceSwitches     int
	minIndependentSources int
	mu                    sync.Mutex
	jobs                  map[string]TransferRequest
	events                map[string]chan TransferResult
}

func NewBroker(cfg BrokerConfig) *Broker {
	q := cfg.QueueSize
	if q <= 0 {
		q = 32
	}
	maxChunkBytes := cfg.MaxChunkBytes
	if maxChunkBytes <= 0 {
		maxChunkBytes = DefaultMaxChunkBytes
	}
	maxArtifactBytes := cfg.MaxArtifactBytes
	if maxArtifactBytes <= 0 {
		maxArtifactBytes = DefaultMaxArtifactBytes
	}
	if maxChunkBytes > DefaultMaxChunkBytes {
		maxChunkBytes = DefaultMaxChunkBytes
	}
	if maxArtifactBytes > DefaultMaxArtifactBytes {
		maxArtifactBytes = DefaultMaxArtifactBytes
	}
	maxSourceSwitches := cfg.MaxSourceSwitches
	if maxSourceSwitches <= 0 {
		maxSourceSwitches = DefaultMaxSourceSwitches
	}
	if maxSourceSwitches > DefaultMaxSourceSwitches {
		maxSourceSwitches = DefaultMaxSourceSwitches
	}
	minIndependentSources := cfg.MinIndependentSources
	if minIndependentSources <= 0 {
		minIndependentSources = 2
	}
	if minIndependentSources > 2 {
		minIndependentSources = 2
	}
	return &Broker{registry: cfg.Registry, store: cfg.ResumeStore, verifier: cfg.LeaseVerifier, queue: make(chan chunkRequest, q), maxChunkBytes: maxChunkBytes, maxArtifactBytes: maxArtifactBytes, maxSourceSwitches: maxSourceSwitches, minIndependentSources: minIndependentSources, jobs: make(map[string]TransferRequest), events: make(map[string]chan TransferResult)}
}

func (b *Broker) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-b.queue:
				b.process(ctx, req)
			}
		}
	}()
}

func (b *Broker) Submit(req TransferRequest) (Job, error) {
	if err := b.validateRequest(req); err != nil {
		return Job{}, err
	}
	source, err := SelectSource(req.Intent, req.Hello, req.Capabilities, nil, nil)
	if err != nil {
		return Job{}, err
	}
	if err := ValidateSourceIndependenceWithMinimum(req.Intent, b.registry, b.minIndependentSources); err != nil {
		return Job{}, err
	}
	if existing, loadErr := b.store.Load(context.Background(), req.Intent.ID); loadErr == nil {
		if !sameIntent(existing.Intent, req.Intent) {
			return Job{}, ErrJobConflict
		}
		if !sourceAvailable(req.Intent, existing.Source, req.Hello, req.Capabilities) || sourceKeyInQuarantines(existing.QuarantinedSources, existing.Source) {
			return Job{}, ErrSourceQuarantined
		}
		b.registerJob(req.Intent.ID, req)
		return Job{ID: existing.JobID, Source: existing.Source, NextOffset: existing.NextOffset}, nil
	} else if !errors.Is(loadErr, ErrJobNotFound) {
		return Job{}, fmt.Errorf("load existing transfer state: %w", loadErr)
	}
	state := ResumeState{JobID: req.Intent.ID, Intent: req.Intent, Source: source, MaxChunk: minInt64(req.Capabilities.MaxChunkSize, b.maxChunkBytes), MaxSourceSwitches: b.maxSourceSwitches, UpdatedAt: time.Now().UTC()}
	if err := b.saveState(context.Background(), 0, state); err != nil {
		// A concurrent identical Submit may have won the first insert. Reload
		// and return that durable state instead of reporting a false conflict.
		if existing, loadErr := b.store.Load(context.Background(), req.Intent.ID); loadErr == nil && sameIntent(existing.Intent, req.Intent) && sourceAvailable(req.Intent, existing.Source, req.Hello, req.Capabilities) && !sourceKeyInQuarantines(existing.QuarantinedSources, existing.Source) {
			b.registerJob(req.Intent.ID, req)
			return Job{ID: existing.JobID, Source: existing.Source, NextOffset: existing.NextOffset}, nil
		}
		return Job{}, fmt.Errorf("save transfer state: %w", err)
	}
	b.registerJob(state.JobID, req)
	return Job{ID: state.JobID, Source: source}, nil
}

func (b *Broker) Resume(id string, req TransferRequest) (TransferResult, error) {
	if err := b.validateRequest(req); err != nil {
		return TransferResult{}, err
	}
	state, err := b.store.Load(context.Background(), id)
	if err != nil {
		return TransferResult{}, err
	}
	if !sameIntent(state.Intent, req.Intent) {
		return TransferResult{}, ErrInvalid
	}
	if !sourceAvailable(req.Intent, state.Source, req.Hello, req.Capabilities) {
		return TransferResult{}, ErrNoSource
	}
	if sourceKeyInQuarantines(state.QuarantinedSources, state.Source) {
		return TransferResult{}, ErrSourceQuarantined
	}
	b.registerJob(id, req)
	return resultFromState(state), nil
}

// QuarantineSource records a source failure and atomically selects the next
// eligible source. It is deliberately explicit: the broker cannot infer that
// a transport endpoint is bad from an arbitrary caller error, and therefore
// never silently bypasses the source policy. Integrity failures reset the
// partial bytes; transport/policy failures may resume from the verified prefix.
func (b *Broker) QuarantineSource(id string, req TransferRequest, failed Source, reason QuarantineReason) (Job, error) {
	if err := b.validateRequest(req); err != nil {
		return Job{}, err
	}
	state, err := b.store.Load(context.Background(), id)
	if err != nil {
		return Job{}, err
	}
	if state.JobID != id || !sameIntent(state.Intent, req.Intent) {
		return Job{}, ErrJobConflict
	}
	if sourceKey(state.Source) != sourceKey(failed) {
		return Job{}, ErrResumeOffsetConflict
	}
	if state.Complete {
		return Job{}, ErrJobTerminal
	}
	wasQuarantined := sourceKeyInQuarantines(state.QuarantinedSources, state.Source)
	if state.Failed && !wasQuarantined {
		return Job{}, ErrJobTerminal
	}
	if state.MaxSourceSwitches <= 0 {
		state.MaxSourceSwitches = DefaultMaxSourceSwitches
	}
	limit := state.MaxSourceSwitches
	if limit > b.maxSourceSwitches {
		limit = b.maxSourceSwitches
	}
	if state.SourceSwitches >= limit && !wasQuarantined {
		state.Failed = true
		state.Failure = ErrSourceSwitchLimit.Error()
		state.UpdatedAt = time.Now().UTC()
		if err := b.saveState(context.Background(), state.NextOffset, state); err != nil {
			return Job{}, err
		}
		return Job{}, ErrSourceSwitchLimit
	}
	quarantines, err := AddSourceQuarantine(state.Intent, state.QuarantinedSources, state.Source, reason)
	if err != nil {
		return Job{}, err
	}
	next, selectErr := b.selectFallback(state.Intent, req.Hello, req.Capabilities, quarantines, reason)
	if selectErr != nil {
		state.QuarantinedSources = quarantines
		if !wasQuarantined {
			state.SourceSwitches++
		}
		state.Failed = true
		state.Failure = selectErr.Error()
		state.UpdatedAt = time.Now().UTC()
		if err := b.saveState(context.Background(), state.NextOffset, state); err != nil {
			return Job{}, err
		}
		return Job{}, selectErr
	}
	expectedOffset := state.NextOffset
	quarantineReason := reason
	if existingReason, ok := quarantineReasonFor(quarantines, state.Source); ok {
		quarantineReason = existingReason
	}
	if quarantineReason == QuarantineIntegrity {
		state.Data = nil
		state.NextOffset = 0
		state.Complete = false
	}
	state.Source = next
	state.QuarantinedSources = quarantines
	if !wasQuarantined {
		state.SourceSwitches++
	}
	state.Failed = false
	state.Failure = ""
	state.UpdatedAt = time.Now().UTC()
	if err := b.saveState(context.Background(), expectedOffset, state); err != nil {
		return Job{}, err
	}
	b.registerJob(id, req)
	return Job{ID: id, Source: next, NextOffset: state.NextOffset}, nil
}

func (b *Broker) validateRequest(req TransferRequest) error {
	if b == nil || b.store == nil || b.verifier == nil {
		return ErrInvalid
	}
	if _, ok := b.store.(AtomicResumeStore); !ok {
		return ErrAtomicResumeRequired
	}
	if err := req.Intent.Validate(); err != nil {
		return err
	}
	if req.Intent.Size > b.maxArtifactBytes {
		return ErrTransferTooLarge
	}
	if _, err := Negotiate(req.Intent, req.Hello, req.Capabilities); err != nil {
		return err
	}
	if err := ValidateSourceIndependenceWithMinimum(req.Intent, b.registry, b.minIndependentSources); err != nil {
		return err
	}
	if !req.Lease.valid() {
		return ErrInvalid
	}
	return b.verifier.VerifyLease(req.Lease)
}

func sourceAvailable(intent DistributionIntent, source Source, hello Hello, capabilities Capabilities) bool {
	selected, err := SelectSource(intent, hello, capabilities, &source, nil)
	return err == nil && sourceKey(selected) == sourceKey(source)
}

func (b *Broker) selectFallback(intent DistributionIntent, hello Hello, capabilities Capabilities, quarantines []SourceQuarantine, reason QuarantineReason) (Source, error) {
	blockedRoots := make(map[string]struct{})
	if reason == QuarantineIntegrity || reason == QuarantinePolicy {
		for _, quarantine := range quarantines {
			registration, ok := b.registry.entries[quarantine.Source.ID]
			if !ok {
				continue
			}
			blockedRoots[registration.Root] = struct{}{}
		}
	}
	filtered := intent
	filtered.Sources = make([]Source, 0, len(intent.Sources))
	for _, source := range intent.Sources {
		if sourceKeyInQuarantines(quarantines, source) {
			continue
		}
		if registration, ok := b.registry.entries[source.ID]; ok {
			if _, blocked := blockedRoots[registration.Root]; blocked {
				continue
			}
		}
		filtered.Sources = append(filtered.Sources, source)
	}
	if len(filtered.Sources) == 0 {
		return Source{}, ErrNoSource
	}
	return SelectSource(filtered, hello, capabilities, nil, nil)
}

func sourceKeyInQuarantines(quarantines []SourceQuarantine, source Source) bool {
	key := sourceKey(source)
	for _, quarantine := range quarantines {
		if sourceKey(quarantine.Source) == key {
			return true
		}
	}
	return false
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (b *Broker) Push(id string, offset int64, data []byte) error {
	b.mu.Lock()
	_, ok := b.jobs[id]
	b.mu.Unlock()
	if !ok {
		return ErrJobNotFound
	}
	if len(data) == 0 {
		return ErrChunkSize
	}
	if int64(len(data)) > b.maxChunkBytes {
		return ErrChunkSize
	}
	request := chunkRequest{id: id, offset: offset, data: append([]byte(nil), data...)}
	select {
	case b.queue <- request:
		return nil
	default:
		return ErrBrokerQueue
	}
}

func (b *Broker) Wait(id string, timeout time.Duration) (TransferResult, error) {
	b.mu.Lock()
	events, ok := b.events[id]
	b.mu.Unlock()
	if !ok {
		return TransferResult{}, ErrJobNotFound
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case result := <-events:
			if result.Complete || result.Failed || result.Retrying {
				return result, result.Failure
			}
		case <-deadline.C:
			return TransferResult{}, context.DeadlineExceeded
		}
	}
}

func (b *Broker) process(ctx context.Context, req chunkRequest) {
	state, err := b.store.Load(ctx, req.id)
	if err != nil {
		b.emit(req.id, TransferResult{JobID: req.id, Failed: true, Failure: err})
		return
	}
	expectedOffset := state.NextOffset
	if state.JobID != req.id || state.NextOffset < 0 || state.NextOffset > state.Intent.Size || int64(len(state.Data)) != state.NextOffset || state.MaxChunk <= 0 || state.MaxChunk > b.maxChunkBytes || state.Intent.Size > b.maxArtifactBytes || state.Intent.Validate() != nil || state.SourceSwitches < 0 || state.SourceSwitches != len(state.QuarantinedSources) || state.SourceSwitches > b.maxSourceSwitches || ValidateSourceQuarantines(state.Intent, state.QuarantinedSources) != nil {
		state.Failed = true
		state.Failure = ErrInvalid.Error()
		state.UpdatedAt = time.Now().UTC()
		if saveErr := b.saveState(ctx, expectedOffset, state); saveErr != nil {
			b.emit(req.id, TransferResult{JobID: req.id, Failed: true, Failure: saveErr})
			return
		}
		result := resultFromState(state)
		result.Failure = ErrInvalid
		b.emit(req.id, result)
		return
	} else if state.Complete || state.Failed {
		b.emit(req.id, resultFromState(state))
		return
	} else if req.offset != state.NextOffset || req.offset < 0 || req.offset > state.Intent.Size || int64(len(req.data)) > state.MaxChunk || int64(len(req.data)) > state.Intent.Size-req.offset {
		err = ErrChunkOverlap
	} else {
		state.Data = append(state.Data, req.data...)
		state.NextOffset += int64(len(req.data))
		if state.NextOffset == state.Intent.Size {
			if err = VerifyDigests(state.Data, state.Intent.Digests); err == nil {
				state.Complete = true
			} else if request, ok := b.requestForJob(req.id); ok {
				failedSource := state.Source
				_, switchErr := b.QuarantineSource(req.id, request, failedSource, QuarantineIntegrity)
				latest, loadErr := b.store.Load(ctx, req.id)
				if loadErr == nil {
					result := resultFromState(latest)
					result.QuarantinedSource = failedSource
					result.Retrying = switchErr == nil
					if !result.Retrying {
						result.Failure = ErrInvalid
					}
					b.emit(req.id, result)
					return
				}
				err = switchErr
			}
		}
	}
	if err != nil {
		state.Failed = true
		state.Failure = err.Error()
	}
	state.UpdatedAt = time.Now().UTC()
	if saveErr := b.saveState(ctx, expectedOffset, state); saveErr != nil {
		if errors.Is(saveErr, ErrResumeOffsetConflict) {
			// Another worker won the CAS. The durable state is still healthy;
			// report a retryable event instead of manufacturing a terminal
			// failure in memory.
			b.emit(req.id, TransferResult{JobID: req.id, NextOffset: expectedOffset, Retrying: true, Failure: saveErr, Source: state.Source})
			return
		}
		err = saveErr
		state.Failed = true
		state.Failure = saveErr.Error()
	}
	result := resultFromState(state)
	if err != nil {
		result.Failure = err
	}
	b.emit(req.id, result)
}

func (b *Broker) saveState(ctx context.Context, expectedOffset int64, state ResumeState) error {
	if atomicStore, ok := b.store.(AtomicResumeStore); ok {
		return atomicStore.SaveExpected(ctx, expectedOffset, state)
	}
	return ErrAtomicResumeRequired
}

func (l LeaseBinding) valid() bool {
	return validIdentifier(l.PluginID) && validIdentifier(l.PluginVersion) && validIdentifier(l.TargetHost) && l.TargetPort > 0 && l.TargetPort <= 65535 && validIdentifier(l.TargetProtocol) && validIdentifier(l.TLSFingerprint) && l.PolicyEpoch != 0 && validIdentifier(l.ConfirmationID)
}

func (b *Broker) emit(id string, result TransferResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	events := b.events[id]
	if events != nil {
		// Keep the newest status. The worker must never lose the terminal event
		// just because a caller did not drain every intermediate offset update.
		if len(events) == cap(events) {
			select {
			case <-events:
			default:
			}
		}
		select {
		case events <- result:
		default:
			// A concurrent sender can fill the channel between the length check
			// and send; dropping the oldest item and retrying keeps this operation
			// non-blocking while preserving the latest status.
			select {
			case <-events:
			default:
			}
			select {
			case events <- result:
			default:
			}
		}
	}
}

func (b *Broker) registerJob(id string, req TransferRequest) {
	b.mu.Lock()
	b.jobs[id] = req
	if _, ok := b.events[id]; !ok {
		b.events[id] = make(chan TransferResult, 16)
	}
	b.mu.Unlock()
}

func (b *Broker) requestForJob(id string) (TransferRequest, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.jobs[id]
	return req, ok
}

func sameIntent(a, b DistributionIntent) bool {
	if a.ID != b.ID || a.PackageID != b.PackageID || a.Version != b.Version || a.Size != b.Size || a.Digests != b.Digests || a.Signature != b.Signature || len(a.Sources) != len(b.Sources) {
		return false
	}
	for i := range a.Sources {
		if a.Sources[i] != b.Sources[i] {
			return false
		}
	}
	return true
}

func sameImmutableState(a, b ResumeState) bool {
	return a.JobID == b.JobID && sameIntent(a.Intent, b.Intent) && a.MaxChunk == b.MaxChunk && (a.MaxSourceSwitches == b.MaxSourceSwitches || a.MaxSourceSwitches == 0 || b.MaxSourceSwitches == 0)
}

// ValidateResumeTransition is the shared transition guard used by in-memory
// and durable stores. A normal transfer can only append bytes. A source change
// is a separate, auditable transition: the old source must be quarantined, the
// switch counter must advance exactly once, and an integrity retry must discard
// the untrusted bytes.
func ValidateResumeTransition(current, next ResumeState) error {
	if !sameImmutableState(current, next) {
		return ErrStateConflict
	}
	if current.NextOffset < 0 || next.NextOffset < 0 || current.NextOffset > current.Intent.Size || next.NextOffset > next.Intent.Size || int64(len(current.Data)) != current.NextOffset || int64(len(next.Data)) != next.NextOffset {
		return ErrResumeOffsetConflict
	}
	if ValidateSourceQuarantines(current.Intent, current.QuarantinedSources) != nil || ValidateSourceQuarantines(next.Intent, next.QuarantinedSources) != nil {
		return ErrInvalid
	}
	if !sourceInIntent(current.Intent, current.Source) || !sourceInIntent(next.Intent, next.Source) {
		return ErrInvalid
	}
	if next.UpdatedAt.Before(current.UpdatedAt) {
		return ErrResumeOffsetConflict
	}
	currentLimit := current.MaxSourceSwitches
	if currentLimit <= 0 || currentLimit > DefaultMaxSourceSwitches {
		currentLimit = DefaultMaxSourceSwitches
	}
	nextLimit := next.MaxSourceSwitches
	if nextLimit == 0 {
		nextLimit = currentLimit
	}
	if nextLimit < 0 || nextLimit > currentLimit {
		return ErrSourceSwitchLimit
	}
	if current.Failed && (current.Source == next.Source || !sourceKeyInQuarantines(current.QuarantinedSources, current.Source)) {
		return ErrJobTerminal
	}
	if len(next.QuarantinedSources) == len(current.QuarantinedSources)+1 {
		if next.SourceSwitches != current.SourceSwitches+1 || next.SourceSwitches != len(next.QuarantinedSources) || next.SourceSwitches > nextLimit || !sameQuarantines(current.QuarantinedSources, next.QuarantinedSources[:len(current.QuarantinedSources)]) {
			return ErrResumeOffsetConflict
		}
		added := next.QuarantinedSources[len(current.QuarantinedSources)]
		if sourceKey(added.Source) != sourceKey(current.Source) || !validQuarantineReason(added.Reason) || sourceKeyInQuarantines(current.QuarantinedSources, added.Source) {
			return ErrResumeOffsetConflict
		}
		if current.Source == next.Source {
			// No alternative source was selected. The job may become terminal,
			// but its bytes must not be rewritten under the same source.
			if !next.Failed || next.Complete || next.Failure == "" || next.NextOffset != current.NextOffset || !bytesEqual(next.Data, current.Data) {
				return ErrResumeOffsetConflict
			}
			return nil
		}
		if next.Complete || next.Failed || next.Failure != "" || sourceKeyInQuarantines(next.QuarantinedSources, next.Source) {
			return ErrResumeOffsetConflict
		}
		if added.Reason == QuarantineIntegrity {
			if next.NextOffset != 0 || len(next.Data) != 0 {
				return ErrResumeOffsetConflict
			}
			return nil
		}
		if next.NextOffset != current.NextOffset || !bytesEqual(next.Data, current.Data) {
			return ErrResumeOffsetConflict
		}
		return nil
	}
	if current.Source != next.Source && len(next.QuarantinedSources) == len(current.QuarantinedSources) {
		// A previous attempt quarantined the current source but no eligible
		// endpoint was available. Once capabilities/policy are refreshed, the
		// same evidence may be reused to select a new source without consuming
		// another failure budget slot.
		if !sourceKeyInQuarantines(current.QuarantinedSources, current.Source) || sourceKeyInQuarantines(next.QuarantinedSources, next.Source) || next.SourceSwitches != current.SourceSwitches || next.Failed || next.Complete || next.Failure != "" {
			return ErrResumeOffsetConflict
		}
		reason, ok := quarantineReasonFor(current.QuarantinedSources, current.Source)
		if !ok {
			return ErrResumeOffsetConflict
		}
		if reason == QuarantineIntegrity {
			if next.NextOffset != 0 || len(next.Data) != 0 {
				return ErrResumeOffsetConflict
			}
		} else if next.NextOffset != current.NextOffset || !bytesEqual(next.Data, current.Data) {
			return ErrResumeOffsetConflict
		}
		return nil
	}
	if current.Source != next.Source || current.SourceSwitches != next.SourceSwitches || !sameQuarantines(current.QuarantinedSources, next.QuarantinedSources) {
		return ErrResumeOffsetConflict
	}
	if next.NextOffset < current.NextOffset || int64(len(next.Data)) < current.NextOffset || !bytesEqual(next.Data[:current.NextOffset], current.Data) {
		return ErrResumeOffsetConflict
	}
	if next.NextOffset == current.NextOffset && !next.Complete && !next.Failed {
		return ErrResumeOffsetConflict
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameQuarantines(a, b []SourceQuarantine) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func resultFromState(state ResumeState) TransferResult {
	result := TransferResult{JobID: state.JobID, NextOffset: state.NextOffset, Complete: state.Complete, Failed: state.Failed, Source: state.Source}
	if state.Failure != "" {
		result.Failure = errors.New(state.Failure)
	}
	return result
}
