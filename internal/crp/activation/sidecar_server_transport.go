package activation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

const (
	sidecarRoutePrefix      = "/v1/crp/sidecars/"
	maxSidecarLauncherSlots = 128
)

var (
	ErrSidecarLauncherConfig  = errors.New("CRP sidecar launcher configuration is invalid")
	ErrSidecarLauncherState   = errors.New("CRP sidecar launcher state conflict")
	ErrSidecarLauncherBackend = errors.New("CRP sidecar launcher backend failed")
)

// SidecarLaunchSpec is the complete immutable input passed to a launcher
// backend. It deliberately contains no command, argument list, executable
// path, working directory, or request URL. Backends must treat every string as
// data and use direct process/container APIs rather than a shell.
type SidecarLaunchSpec struct {
	Descriptor SidecarDescriptor
	Target     RuntimeTarget
}

// SidecarLauncherProcess is the narrow lifecycle surface owned by the HTTPS
// handler after a successful launch. The externally visible handle is created
// by the handler and is never accepted from the backend or used as a path.
type SidecarLauncherProcess interface {
	SetMode(context.Context, SidecarMode) error
	Probe(context.Context) error
	Stop(context.Context) error
}

// SidecarLauncherBackend starts one already-authorized sidecar. Authorization,
// fence validation, state transitions, handles, and request routing remain the
// responsibility of SidecarLauncherHandler.
type SidecarLauncherBackend interface {
	Start(context.Context, SidecarLaunchSpec) (SidecarLauncherProcess, error)
}

type SidecarLauncherHandlerOptions struct {
	ClusterID string
	Role      string
	ClientCA  *x509.CertPool
	Clock     func() time.Time
	Provider  AuthorizationProvider
	Backend   SidecarLauncherBackend
	MaxSlots  int
}

// SidecarLauncherHandler terminates the launcher mTLS protocol used by
// HTTPSidecarManager. It revalidates the live authorization for every request
// but never consumes it; only runtime promotion owns capability consumption.
type SidecarLauncherHandler struct {
	clusterID string
	role      string
	clientCA  *x509.CertPool
	clock     func() time.Time
	provider  AuthorizationProvider
	backend   SidecarLauncherBackend
	maxSlots  int

	mu              sync.Mutex
	byHandle        map[string]*sidecarLauncherRecord
	byAuthorization map[string]*sidecarLauncherRecord
}

type sidecarLauncherRecord struct {
	handle        string
	authorization Authorization
	descriptor    SidecarDescriptor
	target        RuntimeTarget
	ready         chan struct{}

	mu        sync.Mutex
	process   SidecarLauncherProcess
	startErr  error
	mode      SidecarMode
	stopped   bool
	stopTried bool
	stopErr   error
}

func NewSidecarLauncherHandler(opts SidecarLauncherHandlerOptions) (*SidecarLauncherHandler, error) {
	if !validTransportField(opts.ClusterID, 128) {
		return nil, fmt.Errorf("%w: cluster id is required", ErrSidecarLauncherConfig)
	}
	if opts.Role == "" {
		opts.Role = "waf"
	}
	if opts.Role != "waf" || !validTransportField(opts.Role, 32) {
		return nil, fmt.Errorf("%w: role must be waf", ErrSidecarLauncherConfig)
	}
	if opts.ClientCA == nil {
		return nil, fmt.Errorf("%w: client CA is required", ErrSidecarLauncherConfig)
	}
	if isNilActivationDependency(opts.Provider) {
		return nil, fmt.Errorf("%w: authorization provider is required", ErrSidecarLauncherConfig)
	}
	if isNilActivationDependency(opts.Backend) {
		return nil, fmt.Errorf("%w: backend is required", ErrSidecarLauncherConfig)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.MaxSlots == 0 {
		opts.MaxSlots = maxSidecarLauncherSlots
	}
	if opts.MaxSlots < 1 || opts.MaxSlots > maxSidecarLauncherSlots {
		return nil, fmt.Errorf("%w: max slots must be between 1 and %d", ErrSidecarLauncherConfig, maxSidecarLauncherSlots)
	}
	return &SidecarLauncherHandler{
		clusterID:       opts.ClusterID,
		role:            opts.Role,
		clientCA:        opts.ClientCA,
		clock:           opts.Clock,
		provider:        opts.Provider,
		backend:         opts.Backend,
		maxSlots:        opts.MaxSlots,
		byHandle:        make(map[string]*sidecarLauncherRecord),
		byAuthorization: make(map[string]*sidecarLauncherRecord),
	}, nil
}

func (h *SidecarLauncherHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil {
		writeTransportStatus(w, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		writeTransportStatus(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL == nil || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" {
		writeTransportStatus(w, http.StatusBadRequest)
		return
	}
	identity, err := h.peerIdentity(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if r.URL.Path == sidecarStartPath {
		h.handleStart(w, r, identity)
		return
	}
	handle, operation, ok := parseSidecarOperationPath(r.URL.Path)
	if !ok {
		writeTransportStatus(w, http.StatusNotFound)
		return
	}
	h.handleOperation(w, r, identity, handle, operation)
}

func (h *SidecarLauncherHandler) handleStart(w http.ResponseWriter, r *http.Request, identity TransportIdentity) {
	var request SidecarStartRequest
	if !decodeStrictTransportJSON(w, r, &request) {
		return
	}
	if request.SchemaVersion != TransportSchemaVersion || request.Mode != SidecarModeObserve {
		h.writeError(w, ErrAuthorizationBinding)
		return
	}
	if err := h.validateAuthorization(r.Context(), identity, request.Authorization); err != nil {
		h.writeError(w, err)
		return
	}
	if canonicalIdentity(request.Descriptor) != canonicalIdentity(request.Authorization.Request.Descriptor) || request.Target != request.Authorization.Request.Target {
		h.writeError(w, ErrAuthorizationBinding)
		return
	}
	if err := validateLauncherDescriptor(request.Descriptor, request.Target); err != nil {
		h.writeError(w, err)
		return
	}

	record, owner, err := h.reserve(request)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if !owner {
		if err := waitSidecarReady(r.Context(), record); err != nil {
			h.writeError(w, err)
			return
		}
		record.mu.Lock()
		defer record.mu.Unlock()
		if record.startErr != nil {
			h.writeError(w, record.startErr)
			return
		}
		if record.stopped || record.mode != SidecarModeObserve {
			h.writeError(w, ErrSidecarLauncherState)
			return
		}
		writeTransportJSON(w, launcherAcknowledgementLocked(record, "started"))
		return
	}

	process, startErr := h.backend.Start(r.Context(), SidecarLaunchSpec{Descriptor: cloneDescriptor(request.Descriptor), Target: request.Target})
	if startErr != nil || isNilActivationDependency(process) {
		if startErr == nil {
			startErr = errors.New("backend returned a nil process")
		}
		startErr = fmt.Errorf("%w: %v", ErrSidecarLauncherBackend, startErr)
	}
	acknowledgement := record.completeStart(process, startErr)
	if startErr != nil {
		h.writeError(w, startErr)
		return
	}
	// The start request may have entered while authorized and completed after
	// the short-lived grant expired. Do not publish a handle for a process that
	// is already outside its authority window; synchronously reap it instead.
	if !record.authorization.ExpiresAt.After(h.clock().UTC()) {
		if err := h.reapExpired(); err != nil {
			h.writeError(w, err)
			return
		}
		h.writeError(w, ErrAuthorizationDenied)
		return
	}
	writeTransportJSON(w, acknowledgement)
}

func (h *SidecarLauncherHandler) handleOperation(w http.ResponseWriter, r *http.Request, identity TransportIdentity, handle, operation string) {
	var request SidecarOperationRequest
	if !decodeStrictTransportJSON(w, r, &request) {
		return
	}
	if request.SchemaVersion != TransportSchemaVersion || request.HandleID != handle {
		h.writeError(w, ErrAuthorizationBinding)
		return
	}
	var record *sidecarLauncherRecord
	if operation == "stop" {
		record = h.lookup(handle)
		if record == nil {
			writeTransportStatus(w, http.StatusNotFound)
			return
		}
		// Stop narrows exposure and is the only lifecycle operation allowed to
		// use the exact historical authorization after its one-shot capability
		// is consumed or expires. The record, mTLS identity, target and
		// externally supplied handle must all match; this is not a general
		// exemption from authorization validation.
		if err := h.validateStopAuthorization(identity, record, request.Authorization); err != nil {
			h.writeError(w, err)
			return
		}
	} else {
		if err := h.reapExpired(); err != nil {
			h.writeError(w, err)
			return
		}
		if err := h.validateAuthorization(r.Context(), identity, request.Authorization); err != nil {
			h.writeError(w, err)
			return
		}
		record = h.lookup(handle)
		if record == nil {
			writeTransportStatus(w, http.StatusNotFound)
			return
		}
	}
	if err := waitSidecarReady(r.Context(), record); err != nil {
		h.writeError(w, err)
		return
	}

	record.mu.Lock()
	defer record.mu.Unlock()
	if record.startErr != nil {
		h.writeError(w, record.startErr)
		return
	}
	if canonicalIdentity(record.authorization) != canonicalIdentity(request.Authorization) || record.target != request.Authorization.Request.Target {
		h.writeError(w, ErrAuthorizationBinding)
		return
	}
	if record.stopTried && !record.stopped && operation != "stop" {
		h.writeError(w, ErrSidecarLauncherState)
		return
	}
	if request.Mode != record.mode {
		if operation != "mode" {
			h.writeError(w, ErrSidecarLauncherState)
			return
		}
	}

	switch operation {
	case "mode":
		if record.stopped || !validSidecarTransition(record.mode, request.Mode) {
			h.writeError(w, ErrSidecarLauncherState)
			return
		}
		if err := record.process.SetMode(r.Context(), request.Mode); err != nil {
			h.writeError(w, fmt.Errorf("%w: set mode: %v", ErrSidecarLauncherBackend, err))
			return
		}
		record.mode = request.Mode
		writeTransportJSON(w, launcherAcknowledgementLocked(record, "mode_set"))
	case "probe", "health":
		if record.stopped {
			writeTransportStatus(w, http.StatusGone)
			return
		}
		if err := record.process.Probe(r.Context()); err != nil {
			h.writeError(w, fmt.Errorf("%w: health: %v", ErrSidecarLauncherBackend, err))
			return
		}
		writeTransportJSON(w, launcherAcknowledgementLocked(record, "healthy"))
	case "stop":
		if record.stopTried {
			if record.stopErr != nil {
				h.writeError(w, record.stopErr)
				return
			}
			writeTransportJSON(w, launcherAcknowledgementLocked(record, "stopped"))
			return
		}
		record.stopTried = true
		if err := record.process.Stop(r.Context()); err != nil {
			record.stopErr = fmt.Errorf("%w: stop: %v", ErrSidecarLauncherBackend, err)
			h.writeError(w, record.stopErr)
			return
		}
		record.stopped = true
		writeTransportJSON(w, launcherAcknowledgementLocked(record, "stopped"))
	default:
		writeTransportStatus(w, http.StatusNotFound)
	}
}

func (h *SidecarLauncherHandler) reserve(request SidecarStartRequest) (*sidecarLauncherRecord, bool, error) {
	if err := h.reapExpired(); err != nil {
		return nil, false, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(h.clock().UTC())
	if existing := h.byAuthorization[request.Authorization.ID]; existing != nil {
		if canonicalIdentity(existing.authorization) != canonicalIdentity(request.Authorization) || canonicalIdentity(existing.descriptor) != canonicalIdentity(request.Descriptor) || existing.target != request.Target {
			return nil, false, ErrAuthorizationBinding
		}
		return existing, false, nil
	}
	if len(h.byHandle) >= h.maxSlots {
		return nil, false, ErrSidecarLauncherState
	}
	handle, err := newSidecarHandle()
	if err != nil {
		return nil, false, fmt.Errorf("%w: handle generation", ErrSidecarLauncherBackend)
	}
	for h.byHandle[handle] != nil {
		handle, err = newSidecarHandle()
		if err != nil {
			return nil, false, fmt.Errorf("%w: handle generation", ErrSidecarLauncherBackend)
		}
	}
	record := &sidecarLauncherRecord{
		handle: handle, authorization: cloneAuthorization(request.Authorization),
		descriptor: cloneDescriptor(request.Descriptor), target: request.Target,
		ready: make(chan struct{}), mode: SidecarModeObserve,
	}
	h.byHandle[handle] = record
	h.byAuthorization[request.Authorization.ID] = record
	return record, true, nil
}

func (h *SidecarLauncherHandler) pruneLocked(now time.Time) {
	for handle, record := range h.byHandle {
		select {
		case <-record.ready:
		default:
			continue
		}
		if record.authorization.ExpiresAt.After(now) {
			continue
		}
		record.mu.Lock()
		reclaimable := record.stopped || record.startErr != nil
		record.mu.Unlock()
		if !reclaimable {
			continue
		}
		delete(h.byHandle, handle)
		delete(h.byAuthorization, record.authorization.ID)
	}
}

// reapExpired is deliberately synchronous and uses a handler-owned context.
// A cancelled client request must not turn an authorization expiry into an
// unobserved process leak, and background reaper goroutines would make an
// ambiguous Stop result impossible to account for. Backends must honor Stop's
// context contract; a returned error is retained and fails closed.
func (h *SidecarLauncherHandler) reapExpired() error {
	now := h.clock().UTC()
	records := h.expiredRecords(now)
	var firstErr error
	for _, record := range records {
		if err := record.reap(context.Background()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		h.removeReclaimed(record)
	}
	return firstErr
}

func (h *SidecarLauncherHandler) expiredRecords(now time.Time) []*sidecarLauncherRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	records := make([]*sidecarLauncherRecord, 0)
	for _, record := range h.byHandle {
		select {
		case <-record.ready:
		default:
			continue
		}
		if !record.authorization.ExpiresAt.After(now) {
			records = append(records, record)
		}
	}
	return records
}

func (h *SidecarLauncherHandler) removeReclaimed(record *sidecarLauncherRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.byHandle[record.handle] != record {
		return
	}
	record.mu.Lock()
	reclaimable := record.stopped || record.startErr != nil
	record.mu.Unlock()
	if !reclaimable {
		return
	}
	delete(h.byHandle, record.handle)
	delete(h.byAuthorization, record.authorization.ID)
}

func (record *sidecarLauncherRecord) completeStart(process SidecarLauncherProcess, startErr error) SidecarAcknowledgement {
	record.mu.Lock()
	record.process = process
	record.startErr = startErr
	// Snapshot the acknowledgement before publishing ready. Waiting operations
	// may change mode as soon as ready is closed, but a successful start always
	// acknowledges observe mode.
	acknowledgement := launcherAcknowledgementLocked(record, "started")
	close(record.ready)
	record.mu.Unlock()
	return acknowledgement
}

func (record *sidecarLauncherRecord) reap(ctx context.Context) error {
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.startErr != nil || record.stopped {
		return nil
	}
	if record.stopTried {
		if record.stopErr != nil {
			return record.stopErr
		}
		return ErrSidecarLauncherState
	}
	record.stopTried = true
	if err := record.process.Stop(ctx); err != nil {
		record.stopErr = fmt.Errorf("%w: stop expired authorization: %v", ErrSidecarLauncherBackend, err)
		return record.stopErr
	}
	record.stopped = true
	return nil
}

func (h *SidecarLauncherHandler) lookup(handle string) *sidecarLauncherRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byHandle[handle]
}

func (h *SidecarLauncherHandler) validateAuthorization(ctx context.Context, identity TransportIdentity, authorization Authorization) error {
	if authorization.Request.Identity != identity || identity.ClusterID != h.clusterID || identity.Role != h.role {
		return ErrAuthorizationBinding
	}
	if err := validateAuthorization(authorization, authorization.Request, h.clock().UTC()); err != nil {
		return err
	}
	return h.provider.Validate(ctx, identity, authorization)
}

func (h *SidecarLauncherHandler) validateStopAuthorization(identity TransportIdentity, record *sidecarLauncherRecord, authorization Authorization) error {
	if record == nil || authorization.Request.Identity != identity || identity.ClusterID != h.clusterID || identity.Role != h.role {
		return ErrAuthorizationBinding
	}
	if canonicalIdentity(record.authorization) != canonicalIdentity(authorization) || record.target != authorization.Request.Target || record.authorization.Request.Target != record.target {
		return ErrAuthorizationBinding
	}
	return nil
}

func (h *SidecarLauncherHandler) peerIdentity(r *http.Request) (TransportIdentity, error) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return TransportIdentity{}, ErrPeerCertificateRequired
	}
	leaf := r.TLS.PeerCertificates[0]
	var verified []*x509.Certificate
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) > 0 && bytes.Equal(chain[0].Raw, leaf.Raw) {
			verified = chain
			break
		}
	}
	if len(verified) == 0 {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range verified[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: h.clientCA, Intermediates: intermediates, CurrentTime: h.clock().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return TransportIdentity{}, ErrPeerCertificateBinding
	}
	return transportIdentityFromCertificate(leaf, h.clusterID, h.role)
}

func (h *SidecarLauncherHandler) writeError(w http.ResponseWriter, err error) {
	status := http.StatusForbidden
	switch {
	case errors.Is(err, ErrPeerCertificateRequired), errors.Is(err, ErrPeerCertificateBinding), errors.Is(err, ErrTransportTLS):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrAuthorizationNotFound), errors.Is(err, ErrAuthorizationReplay), errors.Is(err, ErrConfirmationBinding), errors.Is(err, ErrSidecarLauncherState):
		status = http.StatusConflict
	case errors.Is(err, ErrAuthorizationDenied), errors.Is(err, ErrFenceExpired):
		status = http.StatusGone
	case errors.Is(err, ErrSidecarLauncherBackend), errors.Is(err, ErrAuthorizationState), errors.Is(err, ErrControlPlaneUnavailable), errors.Is(err, ErrProductionAuditUnavailable), errors.Is(err, ErrProductionDurability), errors.Is(err, ErrProductionContract):
		status = http.StatusServiceUnavailable
	}
	writeTransportStatus(w, status)
}

func parseSidecarOperationPath(value string) (handle, operation string, ok bool) {
	if !strings.HasPrefix(value, sidecarRoutePrefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(value, sidecarRoutePrefix), "/")
	if len(parts) != 2 || !validSidecarHandle(parts[0]) {
		return "", "", false
	}
	switch parts[1] {
	case "mode", "probe", "health", "stop":
		return parts[0], parts[1], true
	default:
		return "", "", false
	}
}

func validateLauncherDescriptor(descriptor SidecarDescriptor, target RuntimeTarget) error {
	allowed := make(map[string]struct{}, len(descriptor.Capabilities))
	for _, capability := range descriptor.Capabilities {
		allowed[capability] = struct{}{}
	}
	if err := validateDescriptor(descriptor, Policy{AllowedCapabilities: allowed}); err != nil {
		return err
	}
	if !validRuntimeTarget(target) || descriptor.PluginID != target.PluginID || descriptor.Namespace != target.Namespace || descriptor.Version != target.Version || descriptor.ManifestIdentity != target.ManifestIdentity || descriptor.ArtifactIdentity != target.ArtifactIdentity {
		return ErrAuthorizationBinding
	}
	if err := crp.ValidateSource(descriptor.Source); err != nil {
		return fmt.Errorf("%w: source", ErrInvalidDescriptor)
	}
	if err := crp.ValidateSourceRoot(descriptor.SourceRoot); err != nil {
		return fmt.Errorf("%w: source root", ErrInvalidDescriptor)
	}
	return nil
}

func validSidecarTransition(current, next SidecarMode) bool {
	return current == SidecarModeObserve && next == SidecarModeCanary || current == SidecarModeCanary && next == SidecarModeActive
}

// launcherAcknowledgementLocked snapshots mutable record state. Callers must
// hold record.mu so acknowledgements cannot race an operation that changes
// mode or stop state.
func launcherAcknowledgementLocked(record *sidecarLauncherRecord, status string) SidecarAcknowledgement {
	return SidecarAcknowledgement{
		SchemaVersion:    TransportSchemaVersion,
		AuthorizationID:  record.authorization.ID,
		RequestID:        record.authorization.Request.RequestID,
		NodeID:           record.authorization.Request.Identity.NodeID,
		HandleID:         record.handle,
		PluginKey:        record.target.Key,
		ManifestIdentity: record.target.ManifestIdentity,
		Mode:             record.mode,
		Status:           status,
	}
}

func waitSidecarReady(ctx context.Context, record *sidecarLauncherRecord) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-record.ready:
		return nil
	}
}

func newSidecarHandle() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "sidecar-" + hex.EncodeToString(raw), nil
}
