// Package activation owns the control-plane lifecycle around CRP runtime
// records. It deliberately keeps sidecar I/O out of request handling: callers
// invoke these methods from an installation/activation worker and the
// RuntimeStore remains the only durable source of truth.
package activation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

var (
	ErrConfig                 = errors.New("invalid CRP activation configuration")
	ErrInvalidDescriptor      = errors.New("invalid CRP sidecar descriptor")
	ErrUnsupportedRuntime     = errors.New("unsupported CRP runtime")
	ErrCapabilityDenied       = errors.New("CRP sidecar capability was denied")
	ErrResourceLimit          = errors.New("CRP sidecar resource request exceeds policy")
	ErrStaleFence             = errors.New("CRP activation fencing token is stale")
	ErrFenceExpired           = errors.New("CRP activation fencing token is expired")
	ErrObserveHealth          = errors.New("CRP observe health check failed")
	ErrCanaryHealth           = errors.New("CRP canary health check failed")
	ErrSidecar                = errors.New("CRP sidecar operation failed")
	ErrAuthorizationInjection = errors.New("raw CRP fence or confirmation injection is forbidden")
	// ErrControlPlaneUnavailable is returned when the protected management
	// entry point cannot obtain a live control-plane fence. Callers must keep
	// the staged/current runtime untouched; this is intentionally a stable
	// fail-closed sentinel for CLI/API adapters.
	ErrControlPlaneUnavailable = errors.New("CRP activation control-plane is unavailable")
	// ErrSidecarUnavailable is returned when no approved sidecar launcher is
	// mounted. A runtime record must never be promoted by a local placeholder.
	ErrSidecarUnavailable = errors.New("CRP activation sidecar is unavailable")
	ErrRollbackRevoked    = errors.New("CRP rollback target is revoked")
	ErrRollbackDowngrade  = errors.New("CRP rollback target is a downgrade")
	ErrRollbackBlocked    = errors.New("CRP rollback target version is blocked")
	ErrAsyncClosed        = errors.New("CRP activation worker is closed")
	ErrAsyncQueueFull     = errors.New("CRP activation worker queue is full")
	ErrAsyncAction        = errors.New("unsupported CRP activation worker action")
)

// SidecarMode controls the sidecar's traffic exposure. Observe is mandatory
// as the first mode for every activation.
type SidecarMode string

const (
	SidecarModeObserve SidecarMode = "observe"
	SidecarModeCanary  SidecarMode = "canary"
	SidecarModeActive  SidecarMode = "active"
)

type Phase string

const (
	PhaseStaged  Phase = "staged"
	PhaseObserve Phase = "observe"
	PhaseCanary  Phase = "canary"
	PhaseActive  Phase = "active"
	PhaseRolled  Phase = "rolled_back"
)

// ResourceRequest is the bounded resource request attached to a descriptor.
// Zero means that the resource is not requested.
type ResourceRequest struct {
	CPUmilli    int64 `json:"cpu_milli,omitempty"`
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	PIDs        int64 `json:"pids,omitempty"`
}

type ResourceLimits struct {
	CPUmilli    int64 `json:"cpu_milli,omitempty"`
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	PIDs        int64 `json:"pids,omitempty"`
}

// SidecarDescriptor is the immutable runtime contract supplied by the
// control plane. Runtime is intentionally a closed set; executable or wasm
// runtimes cannot enter this activation path.
type SidecarDescriptor struct {
	PluginID         string            `json:"plugin_id"`
	Runtime          string            `json:"runtime"`
	Version          string            `json:"version,omitempty"`
	ManifestIdentity string            `json:"manifest_identity,omitempty"`
	ArtifactIdentity string            `json:"artifact_identity,omitempty"`
	Namespace        string            `json:"namespace,omitempty"`
	Source           string            `json:"source,omitempty"`
	SourceRoot       string            `json:"source_root,omitempty"`
	Capabilities     []string          `json:"capabilities,omitempty"`
	Resources        ResourceRequest   `json:"resources,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type StartOptions struct {
	Mode          SidecarMode
	Authorization Authorization
}

type Sidecar interface {
	SetMode(context.Context, SidecarMode) error
	Probe(context.Context) error
	Stop(context.Context) error
}

type SidecarManager interface {
	Start(context.Context, SidecarDescriptor, crp.RuntimeRecord, StartOptions) (Sidecar, error)
	TransportIdentity() TransportIdentity
}

// SidecarLauncher is retained as a descriptive alias for adapters.
type SidecarLauncher = SidecarManager

type Fence struct {
	ClusterID string    `json:"cluster_id"`
	Token     string    `json:"token"`
	Epoch     uint64    `json:"epoch"`
	Revision  uint64    `json:"revision"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CanaryPolicy struct {
	ObserveProbes int           `json:"observe_probes"`
	CanaryProbes  int           `json:"canary_probes"`
	ProbeTimeout  time.Duration `json:"probe_timeout"`
}

type Policy struct {
	AllowedCapabilities map[string]struct{}
	ResourceLimits      ResourceLimits
	ValidateFence       func(context.Context, Fence) error
	// VerifyRecord is the mandatory fresh trust/revocation check. RuntimeStore
	// already authenticates imported packages; this hook binds promotion and
	// rollback to the caller's current trust and revocation snapshot.
	VerifyRecord              func(context.Context, crp.RuntimeRecord) error
	RevokedManifestIdentities map[string]struct{}
	BlockedVersions           map[string]struct{}
}

type Options struct {
	Sidecars         SidecarManager
	ControlPlane     ControlPlaneClient
	Policy           Policy
	Clock            func() time.Time
	AsyncQueueSize   int
	AsyncWorkers     int
	OperationTimeout time.Duration
}

type Service struct {
	store        *crp.RuntimeStore
	sidecars     SidecarManager
	controlPlane ControlPlaneClient
	identity     TransportIdentity
	policy       Policy
	clock        func() time.Time

	mu        sync.Mutex
	clusterID string
	fences    map[string]fenceState
	active    map[string]Sidecar

	asyncMu          sync.Mutex
	asyncWG          sync.WaitGroup
	asyncQueue       chan asyncJob
	asyncContext     context.Context
	asyncCancel      context.CancelFunc
	asyncClosed      bool
	operationTimeout time.Duration
}

type fenceState struct {
	epoch    uint64
	revision uint64
	token    string
}

type InstallResult struct {
	Phase      Phase
	Record     crp.RuntimeRecord
	Descriptor SidecarDescriptor
	Fence      Fence
}

type ActivationResult struct {
	Phase      Phase
	Record     crp.RuntimeRecord
	Descriptor SidecarDescriptor
	Fence      Fence
}

// AsyncRequest is the work item accepted by the activation worker. The
// caller receives a receipt immediately; sidecar probes and runtime I/O run
// on the worker goroutine and never on a protected request thread.
type AsyncRequest struct {
	Action           crp.RuntimeAction
	Key              string
	ExpectedRevision uint64
	Descriptor       SidecarDescriptor
	Policy           CanaryPolicy
	// Fence and Confirmation are retained only so older callers fail closed
	// with ErrAuthorizationInjection instead of silently bypassing the
	// authenticated control-plane exchange.
	Fence        Fence
	Confirmation *crp.Confirmation
}

type asyncJob struct {
	request AsyncRequest
	receipt *AsyncReceipt
	ctx     context.Context
	cancel  context.CancelFunc
}

// AsyncReceipt identifies one queued activation operation.
type AsyncReceipt struct {
	Done <-chan struct{}

	done   chan struct{}
	cancel context.CancelFunc
	mu     sync.Mutex
	result ActivationResult
	err    error
}

// Wait waits for the worker result or context cancellation.
func (r *AsyncReceipt) Wait(ctx context.Context) (ActivationResult, error) {
	if r == nil || r.done == nil {
		return ActivationResult{}, ErrConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ActivationResult{}, ctx.Err()
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.result, r.err
	}
}

// Cancel requests cancellation of a queued or running operation. Cancellation
// never promotes or rolls back local runtime state.
func (r *AsyncReceipt) Cancel() {
	if r != nil && r.cancel != nil {
		r.cancel()
	}
}

func NewService(store *crp.RuntimeStore, opts Options) (*Service, error) {
	if store == nil {
		return nil, ErrConfig
	}
	if opts.ControlPlane == nil {
		return nil, ErrControlPlaneUnavailable
	}
	if opts.Sidecars == nil {
		return nil, ErrSidecarUnavailable
	}
	identity := opts.ControlPlane.TransportIdentity()
	if err := validateTransportIdentity(identity); err != nil {
		return nil, fmt.Errorf("%w: control-plane identity: %v", ErrConfig, err)
	}
	if sidecarIdentity := opts.Sidecars.TransportIdentity(); !sameTransportIdentity(identity, sidecarIdentity) {
		return nil, fmt.Errorf("%w: control-plane and sidecar transports use different node identities", ErrConfig)
	}
	if opts.Policy.VerifyRecord == nil {
		return nil, fmt.Errorf("%w: fresh runtime verification is required", ErrConfig)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.AsyncQueueSize == 0 {
		opts.AsyncQueueSize = 16
	}
	if opts.AsyncQueueSize < 1 {
		return nil, fmt.Errorf("%w: async queue size must be positive", ErrConfig)
	}
	if opts.AsyncWorkers == 0 {
		opts.AsyncWorkers = 1
	}
	if opts.AsyncWorkers < 1 || opts.AsyncWorkers > opts.AsyncQueueSize {
		return nil, fmt.Errorf("%w: async workers must be between 1 and queue size", ErrConfig)
	}
	if opts.OperationTimeout == 0 {
		opts.OperationTimeout = 2 * time.Minute
	}
	if opts.OperationTimeout < time.Second || opts.OperationTimeout > 30*time.Minute {
		return nil, fmt.Errorf("%w: operation timeout must be between 1s and 30m", ErrConfig)
	}
	if opts.Policy.AllowedCapabilities == nil {
		opts.Policy.AllowedCapabilities = map[string]struct{}{"observe": {}}
	}
	opts.Policy = clonePolicy(opts.Policy)
	if err := validateResourceLimits(opts.Policy.ResourceLimits); err != nil {
		return nil, err
	}
	for capability := range opts.Policy.AllowedCapabilities {
		if !validField(capability) {
			return nil, fmt.Errorf("%w: capability %q", ErrConfig, capability)
		}
	}
	workerContext, cancel := context.WithCancel(context.Background())
	service := &Service{
		store: store, sidecars: opts.Sidecars, controlPlane: opts.ControlPlane,
		identity: identity, policy: opts.Policy, clock: opts.Clock,
		fences: make(map[string]fenceState), active: make(map[string]Sidecar),
		asyncQueue: make(chan asyncJob, opts.AsyncQueueSize), asyncContext: workerContext,
		asyncCancel: cancel, operationTimeout: opts.OperationTimeout,
	}
	for i := 0; i < opts.AsyncWorkers; i++ {
		service.asyncWG.Add(1)
		go service.asyncWorker()
	}
	return service, nil
}

// SubmitAsync queues one activation or rollback operation and returns without
// waiting for sidecar startup, probes, verification, or runtime persistence.
// The worker remains bounded by AsyncQueueSize and can be joined with Wait.
func (s *Service) SubmitAsync(ctx context.Context, req AsyncRequest) (*AsyncReceipt, error) {
	if s == nil {
		return nil, ErrConfig
	}
	if req.Action != crp.RuntimeActionPromote && req.Action != crp.RuntimeActionRollback {
		return nil, ErrAsyncAction
	}
	if req.Fence != (Fence{}) || req.Confirmation != nil {
		return nil, ErrAuthorizationInjection
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operationContext, timeoutCancel := context.WithTimeout(s.asyncContext, s.operationTimeout)
	stopCallerCancellation := context.AfterFunc(ctx, timeoutCancel)
	cancel := context.CancelFunc(func() {
		stopCallerCancellation()
		timeoutCancel()
	})
	done := make(chan struct{})
	receipt := &AsyncReceipt{Done: done, done: done, cancel: cancel}
	job := asyncJob{request: req, receipt: receipt, ctx: operationContext, cancel: cancel}
	s.asyncMu.Lock()
	if s.asyncClosed {
		s.asyncMu.Unlock()
		cancel()
		return nil, ErrAsyncClosed
	}
	select {
	case s.asyncQueue <- job:
		s.asyncMu.Unlock()
		return receipt, nil
	default:
		s.asyncMu.Unlock()
		cancel()
		return nil, ErrAsyncQueueFull
	}
}

func (s *Service) asyncWorker() {
	defer s.asyncWG.Done()
	for job := range s.asyncQueue {
		var result ActivationResult
		var err error
		if job.request.Action == crp.RuntimeActionPromote {
			result, err = s.ActivateAuthorized(job.ctx, job.request.Key, job.request.ExpectedRevision, job.request.Descriptor, job.request.Policy)
		} else {
			result, err = s.RollbackAuthorized(job.ctx, job.request.Key, job.request.ExpectedRevision, job.request.Descriptor, job.request.Policy)
		}
		job.cancel()
		job.receipt.mu.Lock()
		job.receipt.result, job.receipt.err = result, err
		job.receipt.mu.Unlock()
		close(job.receipt.done)
	}
}

// CloseAsync stops accepting new worker requests and waits for in-flight
// operations. It does not mutate staged/current runtime state itself.
func (s *Service) CloseAsync() error {
	if s == nil {
		return nil
	}
	s.asyncMu.Lock()
	if s.asyncClosed {
		s.asyncMu.Unlock()
		return nil
	}
	s.asyncClosed = true
	s.asyncCancel()
	close(s.asyncQueue)
	s.asyncMu.Unlock()
	s.asyncWG.Wait()
	return nil
}

// Install rejects the former caller-supplied fence path. Offline admission and
// staging belong to RuntimeStore/`cheesewaf crp stage`; activation authority
// must never be synthesized by an installer.
func (s *Service) Install(context.Context, crp.Package, crp.ImportResult, SidecarDescriptor, Fence) (InstallResult, error) {
	return InstallResult{}, ErrAuthorizationInjection
}

// Activate is the legacy raw-authority entry point. It is retained for source
// compatibility but always fails closed; use ActivateAuthorized or SubmitAsync.
func (s *Service) Activate(context.Context, string, uint64, SidecarDescriptor, CanaryPolicy, Fence, *crp.Confirmation) (ActivationResult, error) {
	return ActivationResult{}, ErrAuthorizationInjection
}

// ActivateAuthorized obtains a short-lived, operation-bound authorization
// over the configured control-plane transport before starting a sidecar.
func (s *Service) ActivateAuthorized(ctx context.Context, key string, expectedRevision uint64, descriptor SidecarDescriptor, policy CanaryPolicy) (ActivationResult, error) {
	if s == nil {
		return ActivationResult{}, ErrConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ActivationResult{}, err
	}
	if err := validateDescriptor(descriptor, s.policy); err != nil {
		return ActivationResult{}, err
	}
	record, err := s.store.Staged(key)
	if err != nil {
		return ActivationResult{}, err
	}
	if record.Revision != expectedRevision {
		return ActivationResult{}, crp.ErrRuntimeConflict
	}
	if err := descriptorMatchesRecord(descriptor, record); err != nil {
		return ActivationResult{}, err
	}
	if err := s.verifyRecord(ctx, record); err != nil {
		return ActivationResult{}, err
	}
	policy, err = normalizeCanaryPolicy(policy)
	if err != nil {
		return ActivationResult{}, err
	}
	authorization, err := s.authorizeOperation(ctx, crp.RuntimeActionPromote, record, expectedRevision, descriptor, policy)
	if err != nil {
		return ActivationResult{}, err
	}
	defer s.controlPlane.Discard(authorization)
	if err := s.preflight(ctx, descriptor, authorization); err != nil {
		return ActivationResult{}, err
	}
	sidecar, err := s.sidecars.Start(ctx, cloneDescriptor(descriptor), record, StartOptions{Mode: SidecarModeObserve, Authorization: authorization})
	if err != nil {
		return ActivationResult{}, fmt.Errorf("%w: start: %w", ErrSidecar, err)
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := runProbes(ctx, sidecar, policy.ObserveProbes, ErrObserveHealth, policy.ProbeTimeout); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := sidecar.SetMode(ctx, SidecarModeCanary); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, fmt.Errorf("%w: canary mode: %v", ErrSidecar, err)
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := runProbes(ctx, sidecar, policy.CanaryProbes, ErrCanaryHealth, policy.ProbeTimeout); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := sidecar.SetMode(ctx, SidecarModeActive); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, fmt.Errorf("%w: active mode: %v", ErrSidecar, err)
	}
	if err := s.verifyRecord(ctx, record); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	confirmation := authorization.Confirmation.RuntimeConfirmation()
	current, err := s.store.Promote(key, expectedRevision, &confirmation)
	if err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	s.replaceActive(key, sidecar)
	return ActivationResult{Phase: PhaseActive, Record: current, Descriptor: cloneDescriptor(descriptor), Fence: authorization.Fence}, nil
}

// Rollback is the legacy raw-authority entry point and always fails closed.
func (s *Service) Rollback(context.Context, string, uint64, SidecarDescriptor, CanaryPolicy, Fence, *crp.Confirmation) (ActivationResult, error) {
	return ActivationResult{}, ErrAuthorizationInjection
}

// RollbackAuthorized asks the control plane for a fresh rollback grant bound
// to the exact last-known-good record and current runtime revision.
func (s *Service) RollbackAuthorized(ctx context.Context, key string, expectedRevision uint64, descriptor SidecarDescriptor, policy CanaryPolicy) (ActivationResult, error) {
	if s == nil {
		return ActivationResult{}, ErrConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ActivationResult{}, err
	}
	if err := validateDescriptor(descriptor, s.policy); err != nil {
		return ActivationResult{}, err
	}
	current, err := s.store.Current(key)
	if err != nil {
		return ActivationResult{}, err
	}
	if current.Revision != expectedRevision {
		return ActivationResult{}, crp.ErrRuntimeConflict
	}
	target, err := s.store.Previous(key)
	if err != nil {
		return ActivationResult{}, err
	}
	if err := descriptorMatchesRecord(descriptor, target); err != nil {
		return ActivationResult{}, err
	}
	if err := rollbackAllowed(current, target); err != nil {
		return ActivationResult{}, err
	}
	if err := s.verifyRollbackRecord(ctx, target); err != nil {
		return ActivationResult{}, err
	}
	policy, err = normalizeCanaryPolicy(policy)
	if err != nil {
		return ActivationResult{}, err
	}
	authorization, err := s.authorizeOperation(ctx, crp.RuntimeActionRollback, target, expectedRevision, descriptor, policy)
	if err != nil {
		return ActivationResult{}, err
	}
	defer s.controlPlane.Discard(authorization)
	if err := s.preflight(ctx, descriptor, authorization); err != nil {
		return ActivationResult{}, err
	}
	sidecar, err := s.sidecars.Start(ctx, cloneDescriptor(descriptor), target, StartOptions{Mode: SidecarModeObserve, Authorization: authorization})
	if err != nil {
		return ActivationResult{}, fmt.Errorf("%w: start: %w", ErrSidecar, err)
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := runProbes(ctx, sidecar, policy.ObserveProbes, ErrObserveHealth, policy.ProbeTimeout); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := sidecar.SetMode(ctx, SidecarModeCanary); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, fmt.Errorf("%w: canary mode: %v", ErrSidecar, err)
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := runProbes(ctx, sidecar, policy.CanaryProbes, ErrCanaryHealth, policy.ProbeTimeout); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := sidecar.SetMode(ctx, SidecarModeActive); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, fmt.Errorf("%w: active mode: %v", ErrSidecar, err)
	}
	if err := s.verifyRollbackRecord(ctx, target); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	if err := s.fenceStillValid(ctx, authorization); err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	confirmation := authorization.Confirmation.RuntimeConfirmation()
	rolled, err := s.store.Rollback(key, expectedRevision, &confirmation)
	if err != nil {
		_ = stopSidecar(sidecar)
		return ActivationResult{}, err
	}
	s.replaceActive(key, sidecar)
	return ActivationResult{Phase: PhaseRolled, Record: rolled, Descriptor: cloneDescriptor(descriptor), Fence: authorization.Fence}, nil
}

func (s *Service) authorizeOperation(ctx context.Context, action crp.RuntimeAction, record crp.RuntimeRecord, expectedRevision uint64, descriptor SidecarDescriptor, policy CanaryPolicy) (Authorization, error) {
	permission, err := permissionForAction(action)
	if err != nil {
		return Authorization{}, err
	}
	requestID, err := newRequestID()
	if err != nil {
		return Authorization{}, fmt.Errorf("%w: request identity generation failed", ErrControlPlaneUnavailable)
	}
	descriptorDigest, err := descriptorIdentity(descriptor)
	if err != nil {
		return Authorization{}, fmt.Errorf("%w: descriptor identity", ErrInvalidDescriptor)
	}
	request := AuthorizationRequest{
		SchemaVersion:      TransportSchemaVersion,
		RequestID:          requestID,
		Identity:           s.identity,
		Action:             action,
		Permission:         permission,
		Target:             runtimeTarget(record),
		ExpectedRevision:   expectedRevision,
		Descriptor:         cloneDescriptor(descriptor),
		DescriptorIdentity: descriptorDigest,
		Canary:             policy,
		RequestedAt:        s.clock().UTC(),
	}
	if err := validateAuthorizationRequest(request, s.identity); err != nil {
		return Authorization{}, err
	}
	authorization, err := s.controlPlane.Authorize(ctx, request)
	if err != nil {
		return Authorization{}, err
	}
	if err := validateAuthorization(authorization, request, s.clock().UTC()); err != nil {
		s.controlPlane.Discard(authorization)
		return Authorization{}, err
	}
	return authorization, nil
}

func (s *Service) preflight(ctx context.Context, descriptor SidecarDescriptor, authorization Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateDescriptor(descriptor, s.policy); err != nil {
		return err
	}
	if err := validateAuthorization(authorization, authorization.Request, s.clock().UTC()); err != nil {
		return err
	}
	if !sameTransportIdentity(authorization.Request.Identity, s.identity) || canonicalIdentity(authorization.Request.Descriptor) != canonicalIdentity(descriptor) {
		return ErrAuthorizationBinding
	}
	if err := s.controlPlane.Validate(ctx, authorization); err != nil {
		return err
	}
	fence := authorization.Fence
	now := s.clock().UTC()
	if !validField(fence.ClusterID) || !validField(fence.Token) || fence.Epoch == 0 || fence.Revision == 0 {
		return ErrStaleFence
	}
	if fence.ExpiresAt.IsZero() || !fence.ExpiresAt.After(now) {
		return ErrFenceExpired
	}
	if s.policy.ValidateFence != nil {
		if err := s.policy.ValidateFence(ctx, fence); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterID == "" {
		s.clusterID = fence.ClusterID
	} else if s.clusterID != fence.ClusterID {
		return ErrStaleFence
	}
	previous, ok := s.fences[fence.ClusterID]
	if ok && fence.Epoch < previous.epoch {
		return ErrStaleFence
	}
	if ok && fence.Epoch == previous.epoch {
		if fence.Revision < previous.revision || (fence.Revision == previous.revision && fence.Token != previous.token) {
			return ErrStaleFence
		}
	}
	s.fences[fence.ClusterID] = fenceState{epoch: fence.Epoch, revision: fence.Revision, token: fence.Token}
	return nil
}

func (s *Service) fenceStillValid(ctx context.Context, authorization Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateAuthorization(authorization, authorization.Request, s.clock().UTC()); err != nil {
		return err
	}
	if err := s.controlPlane.Validate(ctx, authorization); err != nil {
		return err
	}
	fence := authorization.Fence
	if fence.ExpiresAt.IsZero() || !fence.ExpiresAt.After(s.clock().UTC()) {
		return ErrFenceExpired
	}
	if s.policy.ValidateFence != nil {
		if err := s.policy.ValidateFence(ctx, fence); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.fences[fence.ClusterID]
	if !ok || current.epoch != fence.Epoch || current.revision != fence.Revision || current.token != fence.Token {
		return ErrStaleFence
	}
	return nil
}

func validateDescriptor(descriptor SidecarDescriptor, policy Policy) error {
	if !validField(descriptor.PluginID) {
		return fmt.Errorf("%w: plugin ID", ErrInvalidDescriptor)
	}
	if descriptor.Runtime != "sidecar" {
		return ErrUnsupportedRuntime
	}
	if !validField(descriptor.Version) || !validField(descriptor.Namespace) || !validField(descriptor.Source) || !validField(descriptor.SourceRoot) || !validHexDigest(descriptor.ManifestIdentity) || !validHexDigest(descriptor.ArtifactIdentity) {
		return fmt.Errorf("%w: version, namespace, source, source root, manifest identity and artifact identity are required", ErrInvalidDescriptor)
	}
	if err := validateResources(descriptor.Resources, policy.ResourceLimits); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(descriptor.Capabilities))
	for _, capability := range descriptor.Capabilities {
		if !validField(capability) {
			return fmt.Errorf("%w: capability", ErrInvalidDescriptor)
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("%w: duplicate capability %q", ErrInvalidDescriptor, capability)
		}
		seen[capability] = struct{}{}
		if _, allowed := policy.AllowedCapabilities[capability]; !allowed {
			return fmt.Errorf("%w: %s", ErrCapabilityDenied, capability)
		}
	}
	if _, ok := seen["observe"]; !ok {
		return fmt.Errorf("%w: observe capability is required", ErrCapabilityDenied)
	}
	for key, value := range descriptor.Metadata {
		if !validField(key) || !validField(value) {
			return fmt.Errorf("%w: metadata", ErrInvalidDescriptor)
		}
	}
	return nil
}

func validateResourceLimits(limits ResourceLimits) error {
	if limits.CPUmilli < 0 || limits.MemoryBytes < 0 || limits.PIDs < 0 {
		return fmt.Errorf("%w: negative policy limit", ErrConfig)
	}
	return nil
}

func validateResources(req ResourceRequest, limits ResourceLimits) error {
	if req.CPUmilli < 0 || req.MemoryBytes < 0 || req.PIDs < 0 {
		return fmt.Errorf("%w: negative request", ErrResourceLimit)
	}
	if limits.CPUmilli > 0 && req.CPUmilli > limits.CPUmilli || limits.MemoryBytes > 0 && req.MemoryBytes > limits.MemoryBytes || limits.PIDs > 0 && req.PIDs > limits.PIDs {
		return ErrResourceLimit
	}
	return nil
}

func descriptorMatchesRecord(descriptor SidecarDescriptor, record crp.RuntimeRecord) error {
	expectedPluginID := record.PluginID
	if expectedPluginID == "" {
		expectedPluginID = record.Name
	}
	if descriptor.PluginID != expectedPluginID {
		return fmt.Errorf("%w: plugin ID does not match runtime record", ErrInvalidDescriptor)
	}
	if descriptor.Version != record.Version {
		return fmt.Errorf("%w: version does not match runtime record", ErrInvalidDescriptor)
	}
	if descriptor.ManifestIdentity != record.ManifestIdentity {
		return fmt.Errorf("%w: manifest identity does not match runtime record", ErrInvalidDescriptor)
	}
	if descriptor.ArtifactIdentity != record.ArtifactIdentity {
		return fmt.Errorf("%w: artifact identity does not match runtime record", ErrInvalidDescriptor)
	}
	if descriptor.Namespace != record.Namespace {
		return fmt.Errorf("%w: namespace does not match runtime record", ErrInvalidDescriptor)
	}
	return nil
}

// ValidateDescriptorManifestBinding verifies that descriptor claims derived
// from signed package metadata match that metadata exactly. ArtifactIdentity
// is checked separately against RuntimeRecord because it names artifact bytes.
func ValidateDescriptorManifestBinding(descriptor SidecarDescriptor, manifest crp.Manifest) error {
	expectedPluginID := manifest.PluginID
	if expectedPluginID == "" {
		expectedPluginID = manifest.Name
	}
	if descriptor.PluginID != expectedPluginID {
		return fmt.Errorf("%w: plugin ID does not match manifest", ErrInvalidDescriptor)
	}
	if descriptor.Version != manifest.Version {
		return fmt.Errorf("%w: version does not match manifest", ErrInvalidDescriptor)
	}
	if descriptor.Namespace != manifest.Namespace {
		return fmt.Errorf("%w: namespace does not match manifest", ErrInvalidDescriptor)
	}
	if descriptor.Source != manifest.Source {
		return fmt.Errorf("%w: source does not match manifest", ErrInvalidDescriptor)
	}
	if descriptor.SourceRoot != manifest.SourceRoot {
		return fmt.Errorf("%w: source root does not match manifest", ErrInvalidDescriptor)
	}
	identity, err := crp.ContentIdentity(manifest)
	if err != nil || descriptor.ManifestIdentity != identity {
		return fmt.Errorf("%w: manifest identity does not match manifest", ErrInvalidDescriptor)
	}
	return nil
}

func normalizeCanaryPolicy(policy CanaryPolicy) (CanaryPolicy, error) {
	if policy.ObserveProbes < 0 || policy.CanaryProbes < 0 {
		return CanaryPolicy{}, ErrConfig
	}
	if policy.ObserveProbes == 0 {
		policy.ObserveProbes = 1
	}
	if policy.CanaryProbes == 0 {
		policy.CanaryProbes = 1
	}
	return policy, nil
}

func runProbes(ctx context.Context, sidecar Sidecar, count int, sentinel error, timeout time.Duration) error {
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		probeCtx := ctx
		cancel := func() {}
		if timeout > 0 {
			probeCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		err := sidecar.Probe(probeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("%w: probe %d: %w", sentinel, i+1, err)
		}
	}
	return nil
}

func (s *Service) verifyRecord(ctx context.Context, record crp.RuntimeRecord) error {
	if s.policy.VerifyRecord == nil {
		return nil
	}
	if err := s.policy.VerifyRecord(ctx, record); err != nil {
		return fmt.Errorf("%w: %w", crp.ErrRuntimeUnverified, err)
	}
	return nil
}

func (s *Service) verifyRollbackRecord(ctx context.Context, record crp.RuntimeRecord) error {
	if _, blocked := s.policy.RevokedManifestIdentities[record.ManifestIdentity]; blocked {
		return ErrRollbackRevoked
	}
	if _, blocked := s.policy.BlockedVersions[record.Version]; blocked {
		return ErrRollbackBlocked
	}
	if s.policy.VerifyRecord == nil {
		return nil
	}
	if err := s.policy.VerifyRecord(ctx, record); err != nil {
		if errors.Is(err, crp.ErrRevokedSigner) {
			return fmt.Errorf("%w: %w", ErrRollbackRevoked, err)
		}
		return fmt.Errorf("%w: %w", crp.ErrRuntimeUnverified, err)
	}
	return nil
}

func rollbackAllowed(current, target crp.RuntimeRecord) error {
	// The target is obtained only from RuntimeStore.Previous, which is the
	// exact last-known-good pointer created by an earlier atomic promotion.
	// That pointer may legitimately have a lower release sequence/version than
	// the current release. Callers cannot supply an arbitrary downgrade target
	// through this API; explicit blocked versions are checked separately.
	if target.Key == "" || target.Key != current.Key || target.PluginID != current.PluginID {
		return ErrRollbackDowngrade
	}
	return nil
}

func stopSidecar(sidecar Sidecar) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return sidecar.Stop(ctx)
}

func (s *Service) replaceActive(key string, sidecar Sidecar) {
	s.mu.Lock()
	old := s.active[key]
	s.active[key] = sidecar
	s.mu.Unlock()
	if old != nil {
		_ = stopSidecar(old)
	}
}

func cloneDescriptor(descriptor SidecarDescriptor) SidecarDescriptor {
	descriptor.Capabilities = append([]string(nil), descriptor.Capabilities...)
	if descriptor.Metadata != nil {
		descriptor.Metadata = map[string]string{}
		for key, value := range descriptor.Metadata {
			descriptor.Metadata[key] = value
		}
	}
	return descriptor
}

func clonePolicy(policy Policy) Policy {
	policy.AllowedCapabilities = cloneSet(policy.AllowedCapabilities)
	policy.RevokedManifestIdentities = cloneSet(policy.RevokedManifestIdentities)
	policy.BlockedVersions = cloneSet(policy.BlockedVersions)
	return policy
}

func cloneSet(values map[string]struct{}) map[string]struct{} {
	if values == nil {
		return nil
	}
	cloned := make(map[string]struct{}, len(values))
	for key := range values {
		cloned[key] = struct{}{}
	}
	return cloned
}

func validField(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}
