package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

var testTransportIdentity = TransportIdentity{
	ClusterID:         "cluster-a",
	NodeID:            "node-a",
	Role:              "waf",
	CertificateSHA256: strings.Repeat("a", 64),
}

func testApprovalClaim(request AuthorizationRequest) ApprovalClaim {
	return ApprovalClaim{
		ApprovalID:     "approval-" + request.RequestID,
		ConfirmationID: "confirmation-" + request.RequestID,
		Actor:          "operator-a",
		Scope:          ApprovalScope(request),
		PolicyEpoch:    1,
		TTL:            2 * time.Minute,
		IssuedAt:       request.RequestedAt,
		ExpiresAt:      request.RequestedAt.Add(2 * time.Minute),
		IntentDigest:   ApprovalIntentDigest(request),
		Nonce:          "nonce-" + request.RequestID,
		SessionID:      "session-a",
	}
}

type fakeControlPlane struct {
	mu             sync.Mutex
	identity       TransportIdentity
	now            time.Time
	authorizations []AuthorizationRequest
	validations    int
	consumed       []crp.Confirmation
	pending        map[string]WireConfirmation
	failValidateAt int
	validateErr    error
}

func newFakeControlPlane(now time.Time) *fakeControlPlane {
	return &fakeControlPlane{identity: testTransportIdentity, now: now, pending: make(map[string]WireConfirmation)}
}

func (c *fakeControlPlane) TransportIdentity() TransportIdentity { return c.identity }

func (c *fakeControlPlane) Authorize(ctx context.Context, request AuthorizationRequest) (Authorization, error) {
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}
	if err := validateAuthorizationRequest(request, c.identity); err != nil {
		return Authorization{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authorizations = append(c.authorizations, request)
	number := len(c.authorizations)
	expires := c.now.Add(2 * time.Minute)
	confirmation := WireConfirmation{
		ID:               request.ApprovalClaim.ConfirmationID,
		Actor:            request.ApprovalClaim.Actor,
		Action:           request.Action,
		PluginKey:        request.Target.Key,
		ManifestIdentity: request.Target.ManifestIdentity,
		ExpectedRevision: request.ExpectedRevision,
		AuthorizedAt:     c.now,
		ExpiresAt:        expires,
	}
	authorization := Authorization{
		SchemaVersion: TransportSchemaVersion,
		ID:            fmt.Sprintf("authorization-%d", number),
		Request:       request,
		ApprovalClaim: request.ApprovalClaim,
		Fence: Fence{
			ClusterID: c.identity.ClusterID,
			Token:     fmt.Sprintf("fence-%d", number),
			Epoch:     1,
			Revision:  uint64(number),
			ExpiresAt: expires,
		},
		Confirmation: &confirmation,
		IssuedAt:     c.now,
		ExpiresAt:    expires,
	}
	c.pending[confirmation.ID] = confirmation
	return authorization, nil
}

func (c *fakeControlPlane) Validate(ctx context.Context, authorization Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validations++
	if c.failValidateAt > 0 && c.validations >= c.failValidateAt {
		if c.validateErr != nil {
			return c.validateErr
		}
		return ErrAuthorizationDenied
	}
	if authorization.Confirmation == nil {
		return ErrConfirmationBinding
	}
	confirmation, ok := c.pending[authorization.Confirmation.ID]
	if !ok || confirmation != *authorization.Confirmation {
		return ErrConfirmationBinding
	}
	return nil
}

func (c *fakeControlPlane) Consume(_ context.Context, confirmation crp.Confirmation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	wire, ok := c.pending[confirmation.ID]
	if !ok || wire != wireConfirmation(confirmation) {
		return ErrConfirmationBinding
	}
	delete(c.pending, confirmation.ID)
	c.consumed = append(c.consumed, confirmation)
	return nil
}

func (c *fakeControlPlane) Discard(authorization Authorization) {
	if authorization.Confirmation == nil {
		return
	}
	c.mu.Lock()
	delete(c.pending, authorization.Confirmation.ID)
	c.mu.Unlock()
}

type fakeSidecarManager struct {
	mu             sync.Mutex
	identity       TransportIdentity
	starts         []SidecarMode
	authorizations []Authorization
	health         []error
	modes          []SidecarMode
	stopped        int
}

func newFakeSidecarManager() *fakeSidecarManager {
	return &fakeSidecarManager{identity: testTransportIdentity}
}

func (m *fakeSidecarManager) TransportIdentity() TransportIdentity { return m.identity }

func (m *fakeSidecarManager) Start(_ context.Context, _ SidecarDescriptor, _ crp.RuntimeRecord, opts StartOptions) (Sidecar, error) {
	m.mu.Lock()
	m.starts = append(m.starts, opts.Mode)
	m.authorizations = append(m.authorizations, opts.Authorization)
	m.mu.Unlock()
	return &fakeSidecar{manager: m}, nil
}

type fakeSidecar struct{ manager *fakeSidecarManager }

func (s *fakeSidecar) SetMode(_ context.Context, mode SidecarMode) error {
	s.manager.mu.Lock()
	s.manager.modes = append(s.manager.modes, mode)
	s.manager.mu.Unlock()
	return nil
}

func (s *fakeSidecar) Probe(_ context.Context) error {
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	if len(s.manager.health) == 0 {
		return nil
	}
	err := s.manager.health[0]
	s.manager.health = s.manager.health[1:]
	return err
}

func (s *fakeSidecar) Stop(_ context.Context) error {
	s.manager.mu.Lock()
	s.manager.stopped++
	s.manager.mu.Unlock()
	return nil
}

type closeTrackingSidecar struct {
	mu      sync.Mutex
	stops   int
	stopErr error
}

func (s *closeTrackingSidecar) SetMode(context.Context, SidecarMode) error { return nil }
func (s *closeTrackingSidecar) Probe(context.Context) error                { return nil }
func (s *closeTrackingSidecar) Stop(context.Context) error {
	s.mu.Lock()
	s.stops++
	s.mu.Unlock()
	return s.stopErr
}

func (s *closeTrackingSidecar) stopCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stops
}

func activationPackage(t *testing.T, now time.Time, version string, sequence uint64, artifact []byte) (crp.Package, crp.ImportResult) {
	t.Helper()
	manifest := testActivationManifest(artifact)
	manifest.Version = version
	manifest.ReleaseSequence = sequence
	trustKeys := make([]crp.TrustKey, 3)
	privateKeys := make([]ed25519.PrivateKey, 3)
	for i := range privateKeys {
		_, privateKeys[i], _ = ed25519.GenerateKey(rand.Reader)
		trustKeys[i] = crp.TrustKey{ID: fmt.Sprintf("key-%d", i), PublicKey: privateKeys[i].Public().(ed25519.PublicKey), Class: crp.SignerOfficial}
	}
	signatures := make([]crp.Signature, 0, 2)
	for i := 0; i < 2; i++ {
		signature, err := crp.SignManifestWithKeyID(manifest, trustKeys[i].ID, privateKeys[i], now)
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	registry, err := crp.NewSourceRegistry([]crp.SourceRootRegistration{{ID: "root", NamespacePrefixes: []string{"official/"}, Sources: []string{"ota"}}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := crp.NewTrustStore([]crp.TrustRoot{{ID: "root", Class: crp.SignerOfficial, NamespacePrefixes: []string{"official/"}, Keys: trustKeys}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pkg := crp.Package{Manifest: raw, Artifact: artifact, Signatures: signatures}
	imported, err := crp.Import(pkg, crp.ImportOptions{SourceRegistry: registry, TrustStore: trust, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return pkg, imported
}

func testActivationManifest(artifact []byte) crp.Manifest {
	manifest := crp.Manifest{
		APIVersion:      crp.APIVersion,
		Kind:            crp.Kind,
		Name:            "rate-limit",
		PluginID:        "rate-limit",
		Version:         "1.0.0",
		Namespace:       "official/security",
		Source:          "ota",
		SourceRoot:      "root",
		ReleaseSequence: 1,
	}
	manifest.Artifact.Size = int64(len(artifact))
	manifest.Artifact.Name = "plugin.bin"
	manifest.Artifact.Digests = crp.ComputeDigests(artifact)
	manifest.Digests = manifest.Artifact.Digests
	return manifest
}

func newActivationStore(t *testing.T, now time.Time, controlPlane ControlPlaneClient) *crp.RuntimeStore {
	t.Helper()
	authorizer, err := NewRuntimeAuthorizer(controlPlane)
	if err != nil {
		t.Fatal(err)
	}
	store, err := crp.NewRuntimeStore(t.TempDir(), crp.RuntimeStoreOptions{
		Clock:       func() time.Time { return now },
		HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }),
		Revalidate:  crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil }),
		Authorizer:  authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func stageActivationRecord(t *testing.T, store *crp.RuntimeStore, pkg crp.Package, imported crp.ImportResult) crp.RuntimeRecord {
	t.Helper()
	record, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func activationDescriptor(record crp.RuntimeRecord) SidecarDescriptor {
	return SidecarDescriptor{
		PluginID:         record.PluginID,
		Runtime:          "sidecar",
		Version:          record.Version,
		ManifestIdentity: record.ManifestIdentity,
		ArtifactIdentity: record.ArtifactIdentity,
		Namespace:        record.Namespace,
		Source:           "ota",
		SourceRoot:       "root",
		Capabilities:     []string{"observe"},
	}
}

func newActivationService(t *testing.T, store *crp.RuntimeStore, controlPlane ControlPlaneClient, sidecars SidecarManager, now time.Time, policy Policy, optionFns ...func(*Options)) *Service {
	t.Helper()
	if policy.AllowedCapabilities == nil {
		policy.AllowedCapabilities = map[string]struct{}{"observe": {}, "canary": {}}
	}
	if policy.VerifyRecord == nil {
		policy.VerifyRecord = func(context.Context, crp.RuntimeRecord) error { return nil }
	}
	opts := Options{Sidecars: sidecars, ControlPlane: controlPlane, Policy: policy, Clock: func() time.Time { return now }}
	opts.ApprovalClaimResolver = func(_ context.Context, request AuthorizationRequest) (ApprovalClaim, error) {
		return testApprovalClaim(request), nil
	}
	for _, optionFn := range optionFns {
		optionFn(&opts)
	}
	service, err := NewService(store, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.CloseAsync(); err != nil {
			t.Errorf("close activation service: %v", err)
		}
	})
	return service
}

func TestNewServiceRequiresAuthenticatedDependencies(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	sidecars := newFakeSidecarManager()
	tests := []struct {
		name string
		opts Options
		want error
	}{
		{name: "control plane", opts: Options{Sidecars: sidecars, Policy: Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }}}, want: ErrControlPlaneUnavailable},
		{name: "sidecar", opts: Options{ControlPlane: controlPlane, Policy: Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }}}, want: ErrSidecarUnavailable},
		{name: "fresh verification", opts: Options{ControlPlane: controlPlane, Sidecars: sidecars}, want: ErrConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewService(store, tt.opts); !errors.Is(err, tt.want) {
				t.Fatalf("NewService() error = %v, want %v", err, tt.want)
			}
		})
	}
	mismatched := newFakeSidecarManager()
	mismatched.identity.NodeID = "node-b"
	if _, err := NewService(store, Options{ControlPlane: controlPlane, Sidecars: mismatched, Policy: Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }}}); !errors.Is(err, ErrConfig) {
		t.Fatalf("mismatched transport identities error = %v, want ErrConfig", err)
	}
}

func TestServiceFailsClosedWithoutApprovalClaimResolver(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	sidecars := newFakeSidecarManager()
	service, err := NewService(store, Options{
		Sidecars:     sidecars,
		ControlPlane: controlPlane,
		Clock:        func() time.Time { return now },
		Policy:       Policy{AllowedCapabilities: map[string]struct{}{"observe": {}}, VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := service.CloseAsync(); err != nil {
			t.Errorf("close activation service: %v", err)
		}
	}()

	_, err = service.authorizeOperation(context.Background(), crp.RuntimeActionPromote, crp.RuntimeRecord{Key: "rate-limit", PluginID: "rate-limit", Version: "1.0.0", Namespace: "official/security", ManifestIdentity: strings.Repeat("a", 64), ArtifactIdentity: strings.Repeat("b", 64), ReleaseSequence: 1, Revision: 1}, 1, SidecarDescriptor{}, CanaryPolicy{})
	if !errors.Is(err, ErrApprovalClaimUnavailable) {
		t.Fatalf("authorizeOperation() = %v, want ErrApprovalClaimUnavailable", err)
	}
	controlPlane.mu.Lock()
	defer controlPlane.mu.Unlock()
	if len(controlPlane.authorizations) != 0 {
		t.Fatalf("control plane received %d authorization requests without claim", len(controlPlane.authorizations))
	}
}

func TestLegacyAuthorityInjectionAlwaysFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	service := newActivationService(t, store, controlPlane, newFakeSidecarManager(), now, Policy{})
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	descriptor := SidecarDescriptor{}
	fence := Fence{ClusterID: "cluster-a", Token: "injected", Epoch: 1, Revision: 1, ExpiresAt: now.Add(time.Minute)}
	if _, err := service.Install(context.Background(), pkg, imported, descriptor, fence); !errors.Is(err, ErrAuthorizationInjection) {
		t.Fatalf("Install() error = %v, want ErrAuthorizationInjection", err)
	}
	if _, err := service.Activate(context.Background(), "rate-limit", 1, descriptor, CanaryPolicy{}, fence, nil); !errors.Is(err, ErrAuthorizationInjection) {
		t.Fatalf("Activate() error = %v, want ErrAuthorizationInjection", err)
	}
	if _, err := service.Rollback(context.Background(), "rate-limit", 1, descriptor, CanaryPolicy{}, fence, &crp.Confirmation{}); !errors.Is(err, ErrAuthorizationInjection) {
		t.Fatalf("Rollback() error = %v, want ErrAuthorizationInjection", err)
	}
	if _, err := service.SubmitAsync(context.Background(), AsyncRequest{Action: crp.RuntimeActionPromote, Fence: fence}); !errors.Is(err, ErrAuthorizationInjection) {
		t.Fatalf("SubmitAsync() error = %v, want ErrAuthorizationInjection", err)
	}
	if _, err := store.Staged("rate-limit"); !errors.Is(err, crp.ErrRuntimeNotFound) {
		t.Fatalf("legacy Install mutated staged state: %v", err)
	}
}

func TestActivateAuthorizedRunsObserveCanaryThenPromotes(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	sidecars := newFakeSidecarManager()
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{ResourceLimits: ResourceLimits{CPUmilli: 100, MemoryBytes: 1 << 20}})
	descriptor := activationDescriptor(staged)
	descriptor.Resources = ResourceRequest{CPUmilli: 10, MemoryBytes: 1024}

	result, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, descriptor, CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != PhaseActive || result.Record.Slot != crp.RuntimeSlotCurrent {
		t.Fatalf("result = %+v, want active current", result)
	}
	snapshot, err := store.Snapshot(staged.Key)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Current == nil || snapshot.Staged != nil {
		t.Fatalf("snapshot = %+v, want current only", snapshot)
	}
	sidecars.mu.Lock()
	if fmt.Sprint(sidecars.starts) != "[observe]" || fmt.Sprint(sidecars.modes) != "[canary active]" || sidecars.stopped != 0 {
		t.Fatalf("sidecar starts=%v modes=%v stopped=%d", sidecars.starts, sidecars.modes, sidecars.stopped)
	}
	if len(sidecars.authorizations) != 1 || sidecars.authorizations[0].Request.Identity != testTransportIdentity {
		t.Fatalf("sidecar authorization identity was not bound: %+v", sidecars.authorizations)
	}
	sidecars.mu.Unlock()
	controlPlane.mu.Lock()
	defer controlPlane.mu.Unlock()
	if len(controlPlane.authorizations) != 1 || controlPlane.authorizations[0].Permission != PermissionActivate || controlPlane.authorizations[0].Descriptor.Source != "ota" || controlPlane.authorizations[0].Descriptor.SourceRoot != "root" {
		t.Fatalf("authorization request was not fully bound: %+v", controlPlane.authorizations)
	}
	if controlPlane.validations != 6 || len(controlPlane.consumed) != 1 {
		t.Fatalf("validations=%d consumed=%d, want 6 and 1", controlPlane.validations, len(controlPlane.consumed))
	}
}

func TestActivateAuthorizedFailureLeavesStagedAndStopsSidecar(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	sidecars := newFakeSidecarManager()
	sidecars.health = []error{nil, errors.New("canary unavailable")}
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})

	_, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1})
	if !errors.Is(err, ErrCanaryHealth) {
		t.Fatalf("ActivateAuthorized() error = %v, want ErrCanaryHealth", err)
	}
	assertStagedOnly(t, store, staged.Key)
	sidecars.mu.Lock()
	defer sidecars.mu.Unlock()
	if sidecars.stopped != 1 {
		t.Fatalf("stopped=%d, want 1", sidecars.stopped)
	}
}

func TestActivateAuthorizedRevalidatesControlPlaneFenceDuringProgression(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	controlPlane.failValidateAt = 2
	controlPlane.validateErr = ErrStaleFence
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	sidecars := newFakeSidecarManager()
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})

	_, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{})
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("ActivateAuthorized() error = %v, want ErrStaleFence", err)
	}
	assertStagedOnly(t, store, staged.Key)
	sidecars.mu.Lock()
	defer sidecars.mu.Unlock()
	if len(sidecars.starts) != 1 || sidecars.stopped != 1 {
		t.Fatalf("starts=%v stopped=%d, want one start and stop", sidecars.starts, sidecars.stopped)
	}
}

func TestActivateAuthorizedVerifiesFreshRecordBeforeAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	sidecars := newFakeSidecarManager()
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return crp.ErrRevokedSigner }})

	_, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{})
	if !errors.Is(err, crp.ErrRuntimeUnverified) {
		t.Fatalf("ActivateAuthorized() error = %v, want ErrRuntimeUnverified", err)
	}
	controlPlane.mu.Lock()
	authorizations := len(controlPlane.authorizations)
	controlPlane.mu.Unlock()
	sidecars.mu.Lock()
	starts := len(sidecars.starts)
	sidecars.mu.Unlock()
	if authorizations != 0 || starts != 0 {
		t.Fatalf("fresh verification failure reached transport: authorizations=%d starts=%d", authorizations, starts)
	}
}

func TestActivateAuthorizedEnforcesDescriptorPolicyBeforeAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*SidecarDescriptor)
		policy Policy
		want   error
	}{
		{name: "runtime", mutate: func(descriptor *SidecarDescriptor) { descriptor.Runtime = "wasm" }, want: ErrUnsupportedRuntime},
		{name: "capability", mutate: func(descriptor *SidecarDescriptor) { descriptor.Capabilities = []string{"observe", "network"} }, want: ErrCapabilityDenied},
		{name: "resource", mutate: func(descriptor *SidecarDescriptor) { descriptor.Resources.CPUmilli = 101 }, policy: Policy{ResourceLimits: ResourceLimits{CPUmilli: 100}}, want: ErrResourceLimit},
		{name: "record identity", mutate: func(descriptor *SidecarDescriptor) { descriptor.Version = "2.0.0" }, want: ErrInvalidDescriptor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controlPlane := newFakeControlPlane(now)
			store := newActivationStore(t, now, controlPlane)
			pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
			staged := stageActivationRecord(t, store, pkg, imported)
			service := newActivationService(t, store, controlPlane, newFakeSidecarManager(), now, tt.policy)
			descriptor := activationDescriptor(staged)
			tt.mutate(&descriptor)
			if _, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, descriptor, CanaryPolicy{}); !errors.Is(err, tt.want) {
				t.Fatalf("ActivateAuthorized() error = %v, want %v", err, tt.want)
			}
			controlPlane.mu.Lock()
			defer controlPlane.mu.Unlock()
			if len(controlPlane.authorizations) != 0 {
				t.Fatalf("invalid descriptor reached control plane: %+v", controlPlane.authorizations)
			}
		})
	}
}

func TestValidateDescriptorManifestBindingRejectsSourceClaims(t *testing.T) {
	manifest := testActivationManifest([]byte("artifact-v1"))
	manifestIdentity, err := crp.ContentIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := SidecarDescriptor{
		PluginID: manifest.PluginID, Runtime: "sidecar", Version: manifest.Version,
		ManifestIdentity: manifestIdentity, Namespace: manifest.Namespace,
		Source: manifest.Source, SourceRoot: manifest.SourceRoot,
	}
	if err := ValidateDescriptorManifestBinding(descriptor, manifest); err != nil {
		t.Fatalf("matching descriptor error = %v", err)
	}
	descriptor.Source = "peer"
	if err := ValidateDescriptorManifestBinding(descriptor, manifest); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("source mismatch error = %v, want ErrInvalidDescriptor", err)
	}
	descriptor.Source = manifest.Source
	descriptor.SourceRoot = "other-root"
	if err := ValidateDescriptorManifestBinding(descriptor, manifest); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("source-root mismatch error = %v, want ErrInvalidDescriptor", err)
	}
}

func TestRollbackAuthorizedUsesExactPreviousRecord(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	sidecars := newFakeSidecarManager()
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})
	pkg1, imported1 := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	v1 := stageActivationRecord(t, store, pkg1, imported1)
	if _, err := service.ActivateAuthorized(context.Background(), v1.Key, v1.Revision, activationDescriptor(v1), CanaryPolicy{}); err != nil {
		t.Fatal(err)
	}
	pkg2, imported2 := activationPackage(t, now, "2.0.0", 2, []byte("artifact-v2"))
	v2 := stageActivationRecord(t, store, pkg2, imported2)
	active2, err := service.ActivateAuthorized(context.Background(), v2.Key, v2.Revision, activationDescriptor(v2), CanaryPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := store.Previous(v2.Key)
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := service.RollbackAuthorized(context.Background(), v2.Key, active2.Record.Revision, activationDescriptor(previous), CanaryPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Phase != PhaseRolled || rolled.Record.Version != "1.0.0" || rolled.Record.ManifestIdentity != previous.ManifestIdentity {
		t.Fatalf("rollback result = %+v, want exact previous v1", rolled)
	}
	controlPlane.mu.Lock()
	defer controlPlane.mu.Unlock()
	last := controlPlane.authorizations[len(controlPlane.authorizations)-1]
	if last.Action != crp.RuntimeActionRollback || last.Permission != PermissionRollback || last.Target.ManifestIdentity != previous.ManifestIdentity || last.ExpectedRevision != active2.Record.Revision {
		t.Fatalf("rollback authorization was not exact: %+v", last)
	}
}

func TestRollbackAuthorizedRejectsBlockedPreviousBeforeAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	sidecars := newFakeSidecarManager()
	bootstrap := newActivationService(t, store, controlPlane, sidecars, now, Policy{})
	pkg1, imported1 := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	v1 := stageActivationRecord(t, store, pkg1, imported1)
	if _, err := bootstrap.ActivateAuthorized(context.Background(), v1.Key, v1.Revision, activationDescriptor(v1), CanaryPolicy{}); err != nil {
		t.Fatal(err)
	}
	pkg2, imported2 := activationPackage(t, now, "2.0.0", 2, []byte("artifact-v2"))
	v2 := stageActivationRecord(t, store, pkg2, imported2)
	active2, err := bootstrap.ActivateAuthorized(context.Background(), v2.Key, v2.Revision, activationDescriptor(v2), CanaryPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	previous, err := store.Previous(v2.Key)
	if err != nil {
		t.Fatal(err)
	}
	controlPlane.mu.Lock()
	before := len(controlPlane.authorizations)
	controlPlane.mu.Unlock()
	blocked := newActivationService(t, store, controlPlane, sidecars, now, Policy{BlockedVersions: map[string]struct{}{previous.Version: {}}})
	if _, err := blocked.RollbackAuthorized(context.Background(), v2.Key, active2.Record.Revision, activationDescriptor(previous), CanaryPolicy{}); !errors.Is(err, ErrRollbackBlocked) {
		t.Fatalf("RollbackAuthorized() error = %v, want ErrRollbackBlocked", err)
	}
	controlPlane.mu.Lock()
	after := len(controlPlane.authorizations)
	controlPlane.mu.Unlock()
	if after != before {
		t.Fatalf("blocked rollback reached control plane: before=%d after=%d", before, after)
	}
}

func TestSubmitAsyncIsBoundedAndRunsOffCaller(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	manager := &blockingSidecarManager{identity: testTransportIdentity, started: make(chan struct{}), release: make(chan struct{})}
	service := newActivationService(t, store, controlPlane, manager, now, Policy{}, func(opts *Options) {
		opts.AsyncQueueSize = 1
		opts.AsyncWorkers = 1
	})
	request := AsyncRequest{Action: crp.RuntimeActionPromote, Key: staged.Key, ExpectedRevision: staged.Revision, Descriptor: activationDescriptor(staged), Policy: CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1}}
	receipt, err := service.SubmitAsync(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-receipt.Done:
		t.Fatal("async operation completed on the submitting path")
	case <-manager.started:
	case <-time.After(time.Second):
		t.Fatal("sidecar did not start")
	}
	queued, err := service.SubmitAsync(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SubmitAsync(context.Background(), request); !errors.Is(err, ErrAsyncQueueFull) {
		t.Fatalf("third SubmitAsync() error = %v, want ErrAsyncQueueFull", err)
	}
	queued.Cancel()
	close(manager.release)
	if result, err := receipt.Wait(context.Background()); err != nil || result.Phase != PhaseActive {
		t.Fatalf("first receipt result=%+v error=%v", result, err)
	}
	if _, err := queued.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued receipt error=%v, want context.Canceled", err)
	}
}

func TestSubmitAsyncInheritsCallerCancellation(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)
	manager := &blockingSidecarManager{identity: testTransportIdentity, started: make(chan struct{}), release: make(chan struct{})}
	service := newActivationService(t, store, controlPlane, manager, now, Policy{})
	ctx, cancel := context.WithCancel(context.Background())
	receipt, err := service.SubmitAsync(ctx, AsyncRequest{Action: crp.RuntimeActionPromote, Key: staged.Key, ExpectedRevision: staged.Revision, Descriptor: activationDescriptor(staged), Policy: CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.started:
	case <-time.After(time.Second):
		t.Fatal("sidecar did not start")
	}
	cancel()
	if _, err := receipt.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("receipt error=%v, want context.Canceled", err)
	}
	assertStagedOnly(t, store, staged.Key)
}

func TestCloseAsyncStopsActiveSidecarsExactlyOnce(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	sidecars := newFakeSidecarManager()
	service := newActivationService(t, store, controlPlane, sidecars, now, Policy{})
	pkg, imported := activationPackage(t, now, "1.0.0", 1, []byte("artifact-v1"))
	staged := stageActivationRecord(t, store, pkg, imported)

	if _, err := service.ActivateAuthorized(context.Background(), staged.Key, staged.Revision, activationDescriptor(staged), CanaryPolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := service.CloseAsync(); err != nil {
		t.Fatalf("first CloseAsync() error = %v", err)
	}
	if err := service.CloseAsync(); err != nil {
		t.Fatalf("second CloseAsync() error = %v", err)
	}

	sidecars.mu.Lock()
	stopped := sidecars.stopped
	sidecars.mu.Unlock()
	if stopped != 1 {
		t.Fatalf("active sidecars stopped = %d, want 1", stopped)
	}
	service.mu.Lock()
	active := len(service.active)
	service.mu.Unlock()
	if active != 0 {
		t.Fatalf("active sidecars after CloseAsync() = %d, want 0", active)
	}
}

func TestCloseAsyncAggregatesStopErrorsAndRetainsResult(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	service, err := NewService(store, Options{
		Sidecars:     newFakeSidecarManager(),
		ControlPlane: controlPlane,
		Policy:       Policy{AllowedCapabilities: map[string]struct{}{"observe": {}}, VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	firstErr := errors.New("first sidecar stop failed")
	secondErr := errors.New("second sidecar stop failed")
	first := &closeTrackingSidecar{stopErr: firstErr}
	second := &closeTrackingSidecar{stopErr: secondErr}
	service.mu.Lock()
	service.active["first"] = first
	service.active["second"] = second
	service.mu.Unlock()

	closeErr := service.CloseAsync()
	if !errors.Is(closeErr, firstErr) || !errors.Is(closeErr, secondErr) {
		t.Fatalf("CloseAsync() error = %v, want both sidecar stop errors", closeErr)
	}
	service.mu.Lock()
	active := len(service.active)
	service.mu.Unlock()
	if active != 0 {
		t.Fatalf("active sidecars after CloseAsync() = %d, want 0", active)
	}
	if first.stopCount() != 1 || second.stopCount() != 1 {
		t.Fatalf("sidecar stop counts = %d, %d, want 1, 1", first.stopCount(), second.stopCount())
	}

	if repeatErr := service.CloseAsync(); !errors.Is(repeatErr, firstErr) || !errors.Is(repeatErr, secondErr) {
		t.Fatalf("repeated CloseAsync() error = %v, want retained stop errors", repeatErr)
	}
	if first.stopCount() != 1 || second.stopCount() != 1 {
		t.Fatalf("repeated close stop counts = %d, %d, want 1, 1", first.stopCount(), second.stopCount())
	}
}

func TestCloseAsyncConcurrentCallersShareResult(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	controlPlane := newFakeControlPlane(now)
	store := newActivationStore(t, now, controlPlane)
	service, err := NewService(store, Options{
		Sidecars:     newFakeSidecarManager(),
		ControlPlane: controlPlane,
		Policy:       Policy{AllowedCapabilities: map[string]struct{}{"observe": {}}, VerifyRecord: func(context.Context, crp.RuntimeRecord) error { return nil }},
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	stopErr := errors.New("concurrent close stop failed")
	sidecar := &closeTrackingSidecar{stopErr: stopErr}
	service.mu.Lock()
	service.active["concurrent"] = sidecar
	service.mu.Unlock()

	const callers = 16
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- service.CloseAsync()
		}()
	}
	wg.Wait()
	close(results)
	for closeErr := range results {
		if !errors.Is(closeErr, stopErr) {
			t.Fatalf("concurrent CloseAsync() error = %v, want %v", closeErr, stopErr)
		}
	}
	if got := sidecar.stopCount(); got != 1 {
		t.Fatalf("concurrent sidecar stop count = %d, want 1", got)
	}
}

func TestRollbackAllowedRejectsArbitraryTarget(t *testing.T) {
	current := crp.RuntimeRecord{Key: "rate-limit", PluginID: "rate-limit", Version: "2.0.0", ReleaseSequence: 2}
	arbitrary := crp.RuntimeRecord{Key: "other", PluginID: "rate-limit", Version: "0.1.0"}
	if err := rollbackAllowed(current, arbitrary); !errors.Is(err, ErrRollbackDowngrade) {
		t.Fatalf("rollbackAllowed() error = %v, want ErrRollbackDowngrade", err)
	}
}

func assertStagedOnly(t *testing.T, store *crp.RuntimeStore, key string) {
	t.Helper()
	if _, err := store.Staged(key); err != nil {
		t.Fatalf("staged record missing: %v", err)
	}
	if _, err := store.Current(key); !errors.Is(err, crp.ErrRuntimeNotFound) {
		t.Fatalf("current record exists after failed activation: %v", err)
	}
}

type blockingSidecarManager struct {
	identity TransportIdentity
	started  chan struct{}
	release  chan struct{}
}

func (m *blockingSidecarManager) TransportIdentity() TransportIdentity { return m.identity }

func (m *blockingSidecarManager) Start(_ context.Context, _ SidecarDescriptor, _ crp.RuntimeRecord, _ StartOptions) (Sidecar, error) {
	select {
	case <-m.started:
	default:
		close(m.started)
	}
	return &blockingSidecar{manager: m}, nil
}

type blockingSidecar struct{ manager *blockingSidecarManager }

func (s *blockingSidecar) SetMode(context.Context, SidecarMode) error { return nil }

func (s *blockingSidecar) Probe(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.manager.release:
		return nil
	}
}

func (s *blockingSidecar) Stop(context.Context) error { return nil }
