package cli

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
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

var crpActivationAdapterIdentity = activation.TransportIdentity{
	ClusterID:         "cluster-a",
	NodeID:            "node-a",
	Role:              "waf",
	CertificateSHA256: strings.Repeat("a", 64),
}

func TestNewProductionCRPActivationExecutorRequiresService(t *testing.T) {
	if _, err := NewProductionCRPActivationExecutor(nil); !errors.Is(err, ErrProductionCRPUnavailable) {
		t.Fatalf("NewProductionCRPActivationExecutor(nil) error = %v, want ErrProductionCRPUnavailable", err)
	}
}

func TestProductionCRPActivationExecutorWaitsForFinalResult(t *testing.T) {
	fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{})
	executor, err := NewProductionCRPActivationExecutor(fixture.service)
	if err != nil {
		t.Fatal(err)
	}

	result, err := executor.ExecuteCRPActivation(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("ExecuteCRPActivation() error = %v", err)
	}
	if result.Phase != activation.PhaseActive || result.Record.Key != fixture.record.Key || result.Record.Revision <= fixture.record.Revision {
		t.Fatalf("ExecuteCRPActivation() result = %+v, want final active record after staged revision %d", result, fixture.record.Revision)
	}
	current, err := fixture.store.Current(fixture.record.Key)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if current.Revision != result.Record.Revision {
		t.Fatalf("current revision = %d, result revision = %d", current.Revision, result.Record.Revision)
	}
}

func TestProductionCRPActivationExecutorPropagatesCancellation(t *testing.T) {
	resolverStarted := make(chan struct{})
	fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{
		resolver: func(ctx context.Context, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
			close(resolverStarted)
			<-ctx.Done()
			return activation.ApprovalClaim{}, ctx.Err()
		},
	})
	executor, err := NewProductionCRPActivationExecutor(fixture.service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, executeErr := executor.ExecuteCRPActivation(ctx, fixture.request)
		result <- executeErr
	}()
	select {
	case <-resolverStarted:
	case <-time.After(time.Second):
		t.Fatal("activation worker did not reach approval resolver")
	}
	cancel()
	select {
	case executeErr := <-result:
		if !errors.Is(executeErr, context.Canceled) {
			t.Fatalf("ExecuteCRPActivation() error = %v, want context.Canceled", executeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("ExecuteCRPActivation() did not return after context cancellation")
	}
}

func TestProductionCRPActivationExecutorPropagatesQueueFull(t *testing.T) {
	resolverStarted := make(chan struct{})
	fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{
		queueSize: 1,
		resolver: func(ctx context.Context, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
			select {
			case <-resolverStarted:
			default:
				close(resolverStarted)
			}
			<-ctx.Done()
			return activation.ApprovalClaim{}, ctx.Err()
		},
	})
	first, err := fixture.service.SubmitAsync(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-resolverStarted:
	case <-time.After(time.Second):
		t.Fatal("activation worker did not start first request")
	}
	queued, err := fixture.service.SubmitAsync(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		first.Cancel()
		queued.Cancel()
		_, _ = first.Wait(context.Background())
		_, _ = queued.Wait(context.Background())
	})

	executor, err := NewProductionCRPActivationExecutor(fixture.service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ExecuteCRPActivation(context.Background(), fixture.request); !errors.Is(err, activation.ErrAsyncQueueFull) {
		t.Fatalf("ExecuteCRPActivation() error = %v, want ErrAsyncQueueFull", err)
	}
}

func TestProductionCRPActivationExecutorPropagatesAuthorizationAndRuntimeErrors(t *testing.T) {
	t.Run("approval claim unavailable", func(t *testing.T) {
		fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{disableResolver: true})
		executor, err := NewProductionCRPActivationExecutor(fixture.service)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := executor.ExecuteCRPActivation(context.Background(), fixture.request); !errors.Is(err, activation.ErrApprovalClaimUnavailable) {
			t.Fatalf("ExecuteCRPActivation() error = %v, want ErrApprovalClaimUnavailable", err)
		}
	})

	t.Run("control-plane authorization denied", func(t *testing.T) {
		fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{authorizeErr: activation.ErrAuthorizationDenied})
		executor, err := NewProductionCRPActivationExecutor(fixture.service)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := executor.ExecuteCRPActivation(context.Background(), fixture.request); !errors.Is(err, activation.ErrAuthorizationDenied) {
			t.Fatalf("ExecuteCRPActivation() error = %v, want ErrAuthorizationDenied", err)
		}
	})

	t.Run("runtime revision conflict", func(t *testing.T) {
		fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{})
		executor, err := NewProductionCRPActivationExecutor(fixture.service)
		if err != nil {
			t.Fatal(err)
		}
		request := fixture.request
		request.ExpectedRevision++
		if _, err := executor.ExecuteCRPActivation(context.Background(), request); !errors.Is(err, crp.ErrRuntimeConflict) {
			t.Fatalf("ExecuteCRPActivation() error = %v, want ErrRuntimeConflict", err)
		}
	})
}

func TestProductionCRPActivationExecutorRejectsCallerAuthority(t *testing.T) {
	fixture := newCRPActivationAdapterFixture(t, crpActivationAdapterFixtureOptions{})
	executor, err := NewProductionCRPActivationExecutor(fixture.service)
	if err != nil {
		t.Fatal(err)
	}

	requests := []activation.AsyncRequest{fixture.request, fixture.request}
	requests[0].Fence = activation.Fence{ClusterID: "cluster-a", Token: "injected", Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
	requests[1].Confirmation = &crp.Confirmation{ID: "injected"}
	for _, request := range requests {
		if _, err := executor.ExecuteCRPActivation(context.Background(), request); !errors.Is(err, activation.ErrAuthorizationInjection) {
			t.Fatalf("ExecuteCRPActivation() error = %v, want ErrAuthorizationInjection", err)
		}
	}
	if _, err := fixture.store.Current(fixture.record.Key); !errors.Is(err, crp.ErrRuntimeNotFound) {
		t.Fatalf("caller authority mutated runtime: Current() error = %v", err)
	}
}

type crpActivationAdapterFixtureOptions struct {
	resolver        activation.ApprovalClaimResolver
	disableResolver bool
	authorizeErr    error
	queueSize       int
}

type crpActivationAdapterFixture struct {
	service *activation.Service
	store   *crp.RuntimeStore
	record  crp.RuntimeRecord
	request activation.AsyncRequest
}

func newCRPActivationAdapterFixture(t *testing.T, opts crpActivationAdapterFixtureOptions) crpActivationAdapterFixture {
	t.Helper()
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	controlPlane := &crpActivationAdapterControlPlane{
		identity:     crpActivationAdapterIdentity,
		now:          now,
		authorizeErr: opts.authorizeErr,
	}
	authorizer, err := activation.NewRuntimeAuthorizer(controlPlane)
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
	pkg, imported := newCRPActivationAdapterPackage(t, now)
	record, err := store.Stage(pkg, imported)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := activation.SidecarDescriptor{
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
	resolver := opts.resolver
	if resolver == nil && !opts.disableResolver {
		resolver = func(_ context.Context, request activation.AuthorizationRequest) (activation.ApprovalClaim, error) {
			return crpActivationAdapterApprovalClaim(request), nil
		}
	}
	queueSize := opts.queueSize
	if queueSize == 0 {
		queueSize = 4
	}
	service, err := activation.NewService(store, activation.Options{
		Sidecars:              crpActivationAdapterSidecars{},
		ControlPlane:          controlPlane,
		ApprovalClaimResolver: resolver,
		Policy: activation.Policy{
			AllowedCapabilities: map[string]struct{}{"observe": {}},
			VerifyRecord:        func(context.Context, crp.RuntimeRecord) error { return nil },
		},
		Clock:            func() time.Time { return now },
		AsyncQueueSize:   queueSize,
		AsyncWorkers:     1,
		OperationTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.CloseAsync(); err != nil {
			t.Errorf("CloseAsync() error = %v", err)
		}
	})
	return crpActivationAdapterFixture{
		service: service,
		store:   store,
		record:  record,
		request: activation.AsyncRequest{
			Action:           crp.RuntimeActionPromote,
			Key:              record.Key,
			ExpectedRevision: record.Revision,
			Descriptor:       descriptor,
			Policy:           activation.CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1, ProbeTimeout: time.Second},
		},
	}
}

func newCRPActivationAdapterPackage(t *testing.T, now time.Time) (crp.Package, crp.ImportResult) {
	return newCRPActivationAdapterPackageRelease(t, now, "1.0.0", 1, []byte("adapter-test-artifact"))
}

func newCRPActivationAdapterPackageRelease(t *testing.T, now time.Time, version string, sequence uint64, artifact []byte) (crp.Package, crp.ImportResult) {
	t.Helper()
	manifest := crp.Manifest{
		APIVersion:      crp.APIVersion,
		Kind:            crp.Kind,
		Name:            "adapter-test",
		PluginID:        "adapter-test",
		Version:         version,
		Namespace:       "official/security",
		Source:          "ota",
		SourceRoot:      "root",
		ReleaseSequence: sequence,
	}
	manifest.Artifact.Size = int64(len(artifact))
	manifest.Artifact.Name = "plugin.bin"
	manifest.Artifact.Digests = crp.ComputeDigests(artifact)
	manifest.Digests = manifest.Artifact.Digests

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
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pkg := crp.Package{Manifest: rawManifest, Artifact: artifact, Signatures: signatures}
	imported, err := crp.Import(pkg, crp.ImportOptions{SourceRegistry: registry, TrustStore: trust, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return pkg, imported
}

func crpActivationAdapterApprovalClaim(request activation.AuthorizationRequest) activation.ApprovalClaim {
	expiresAt := request.RequestedAt.Add(2 * time.Minute)
	return activation.ApprovalClaim{
		ApprovalID:     "approval-" + request.RequestID,
		ConfirmationID: "confirmation-" + request.RequestID,
		Actor:          "operator-a",
		Scope:          activation.ApprovalScope(request),
		PolicyEpoch:    1,
		TTL:            2 * time.Minute,
		IssuedAt:       request.RequestedAt,
		ExpiresAt:      expiresAt,
		IntentDigest:   activation.ApprovalIntentDigest(request),
		Nonce:          "nonce-" + request.RequestID,
		SessionID:      "session-a",
	}
}

type crpActivationAdapterControlPlane struct {
	mu           sync.Mutex
	identity     activation.TransportIdentity
	now          time.Time
	authorizeErr error
	nextFence    uint64
}

func (c *crpActivationAdapterControlPlane) TransportIdentity() activation.TransportIdentity {
	return c.identity
}

func (c *crpActivationAdapterControlPlane) Authorize(ctx context.Context, request activation.AuthorizationRequest) (activation.Authorization, error) {
	if err := ctx.Err(); err != nil {
		return activation.Authorization{}, err
	}
	if c.authorizeErr != nil {
		return activation.Authorization{}, c.authorizeErr
	}
	c.mu.Lock()
	c.nextFence++
	fenceRevision := c.nextFence
	c.mu.Unlock()
	expiresAt := c.now.Add(time.Minute)
	confirmation := activation.WireConfirmation{
		ID:               request.ApprovalClaim.ConfirmationID,
		Actor:            request.ApprovalClaim.Actor,
		Action:           request.Action,
		PluginKey:        request.Target.Key,
		ManifestIdentity: request.Target.ManifestIdentity,
		ExpectedRevision: request.ExpectedRevision,
		AuthorizedAt:     c.now,
		ExpiresAt:        expiresAt,
	}
	return activation.Authorization{
		SchemaVersion: activation.TransportSchemaVersion,
		ID:            fmt.Sprintf("authorization-%d", fenceRevision),
		Request:       request,
		ApprovalClaim: request.ApprovalClaim,
		Fence: activation.Fence{
			ClusterID: c.identity.ClusterID,
			Token:     fmt.Sprintf("fence-%d", fenceRevision),
			Epoch:     1,
			Revision:  fenceRevision,
			ExpiresAt: expiresAt,
		},
		Confirmation: &confirmation,
		IssuedAt:     c.now,
		ExpiresAt:    expiresAt,
	}, nil
}

func (c *crpActivationAdapterControlPlane) Validate(ctx context.Context, _ activation.Authorization) error {
	return ctx.Err()
}

func (c *crpActivationAdapterControlPlane) Consume(ctx context.Context, _ crp.Confirmation) error {
	return ctx.Err()
}

func (*crpActivationAdapterControlPlane) Discard(activation.Authorization) {}

type crpActivationAdapterSidecars struct{}

func (crpActivationAdapterSidecars) TransportIdentity() activation.TransportIdentity {
	return crpActivationAdapterIdentity
}

func (crpActivationAdapterSidecars) Start(context.Context, activation.SidecarDescriptor, crp.RuntimeRecord, activation.StartOptions) (activation.Sidecar, error) {
	return crpActivationAdapterSidecar{}, nil
}

type crpActivationAdapterSidecar struct{}

func (crpActivationAdapterSidecar) SetMode(context.Context, activation.SidecarMode) error { return nil }
func (crpActivationAdapterSidecar) Probe(context.Context) error                           { return nil }
func (crpActivationAdapterSidecar) Stop(context.Context) error                            { return nil }
