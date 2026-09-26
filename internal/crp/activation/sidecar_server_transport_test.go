package activation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

type launcherProviderFake struct {
	mu          sync.Mutex
	validateErr error
	validates   int
	consumes    int
}

func (*launcherProviderFake) Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, errors.New("unexpected launcher authorize")
}

func (p *launcherProviderFake) Validate(context.Context, TransportIdentity, Authorization) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.validates++
	return p.validateErr
}

func (p *launcherProviderFake) Consume(context.Context, TransportIdentity, Authorization) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumes++
	return errors.New("unexpected launcher consume")
}

func (p *launcherProviderFake) counts() (validates, consumes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validates, p.consumes
}

func (p *launcherProviderFake) setValidateError(err error) {
	p.mu.Lock()
	p.validateErr = err
	p.mu.Unlock()
}

type launcherBackendFake struct {
	mu       sync.Mutex
	startErr error
	starts   int
	specs    []SidecarLaunchSpec
	process  *launcherProcessFake
	started  chan struct{}
	release  chan struct{}
}

func (b *launcherBackendFake) Start(ctx context.Context, spec SidecarLaunchSpec) (SidecarLauncherProcess, error) {
	b.mu.Lock()
	b.starts++
	b.specs = append(b.specs, spec)
	started, release := b.started, b.release
	process, err := b.process, b.startErr
	b.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
	}
	if process == nil {
		process = &launcherProcessFake{}
	}
	return process, err
}

func (b *launcherBackendFake) startCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.starts
}

type launcherProcessFake struct {
	mu       sync.Mutex
	modeErr  error
	probeErr error
	stopErr  error
	modes    []SidecarMode
	probes   int
	stops    int
}

func (p *launcherProcessFake) SetMode(_ context.Context, mode SidecarMode) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.modes = append(p.modes, mode)
	return p.modeErr
}

func (p *launcherProcessFake) Probe(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probes++
	return p.probeErr
}

func (p *launcherProcessFake) Stop(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stops++
	return p.stopErr
}

func (p *launcherProcessFake) snapshot() (modes []SidecarMode, probes, stops int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]SidecarMode(nil), p.modes...), p.probes, p.stops
}

type launcherClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *launcherClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *launcherClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func TestSidecarLauncherHandlerServesHTTPSidecarManagerWithoutConsumingAuthorization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	roots := launcherRoots(t, pki.clientBundle.CAPEM)
	provider := &launcherProviderFake{}
	process := &launcherProcessFake{}
	backend := &launcherBackendFake{process: process}
	handler, err := NewSidecarLauncherHandler(SidecarLauncherHandlerOptions{
		ClusterID: "cluster-a", ClientCA: roots, Clock: func() time.Time { return now },
		Provider: provider, Backend: backend,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := pki.newServer(t, "sidecar-launcher", handler)
	caFile, certFile, keyFile := writeMTLSBundleFiles(t, pki.clientBundle, 0o600)
	transport, err := NewMTLSClient(MTLSOptions{
		CAFile: caFile, CertFile: certFile, KeyFile: keyFile,
		ClusterID: "cluster-a", NodeID: "node-a", Role: "waf",
		ServerName: "sidecar-launcher", Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewHTTPSidecarManager(server.server.URL, transport, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	descriptor := launcherDescriptor()
	record := launcherRecord(descriptor)
	authorization := launcherAuthorization(t, now, transport.TransportIdentity(), descriptor, runtimeTarget(record))

	sidecar, err := manager.Start(t.Context(), descriptor, record, StartOptions{Mode: SidecarModeObserve, Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	if err := sidecar.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.SetMode(t.Context(), SidecarModeCanary); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.SetMode(t.Context(), SidecarModeActive); err != nil {
		t.Fatal(err)
	}
	// A successful promotion consumes the one-shot authorization. Cleanup is
	// still allowed with the exact handler-owned authorization, handle, target
	// and mTLS identity; otherwise every active production sidecar would become
	// impossible to stop during shutdown.
	provider.setValidateError(ErrAuthorizationReplay)
	if err := sidecar.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.Stop(t.Context()); err != nil {
		t.Fatalf("local idempotent stop: %v", err)
	}

	if backend.startCount() != 1 {
		t.Fatalf("backend starts=%d, want 1", backend.startCount())
	}
	modes, probes, stops := process.snapshot()
	if len(modes) != 2 || modes[0] != SidecarModeCanary || modes[1] != SidecarModeActive || probes != 2 || stops != 1 {
		t.Fatalf("backend lifecycle modes=%v probes=%d stops=%d", modes, probes, stops)
	}
	validates, consumes := provider.counts()
	if validates != 5 || consumes != 0 {
		t.Fatalf("provider validates=%d consumes=%d, want 5 and 0", validates, consumes)
	}
}

func TestSidecarLauncherHandlerEnforcesBindingTransitionAndIdempotency(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	provider := &launcherProviderFake{}
	process := &launcherProcessFake{}
	backend := &launcherBackendFake{process: process}
	handler := mustLauncherHandler(t, now, launcherRoots(t, pki.clientBundle.CAPEM), provider, backend)

	start := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization,
		Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	if start.Code != http.StatusOK {
		t.Fatalf("start status=%d", start.Code)
	}
	ack := decodeLauncherAck(t, start)

	invalidTransition := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "mode"), SidecarOperationRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization,
		HandleID: ack.HandleID, Mode: SidecarModeActive,
	})
	if invalidTransition.Code != http.StatusConflict {
		t.Fatalf("observe->active status=%d, want conflict", invalidTransition.Code)
	}
	mode := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "mode"), SidecarOperationRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization,
		HandleID: ack.HandleID, Mode: SidecarModeCanary,
	})
	if mode.Code != http.StatusOK {
		t.Fatalf("observe->canary status=%d", mode.Code)
	}
	health := callLauncherHandler(t, handler, leaf, true, sidecarRoutePrefix+ack.HandleID+"/health", SidecarOperationRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization,
		HandleID: ack.HandleID, Mode: SidecarModeCanary,
	})
	if health.Code != http.StatusOK || decodeLauncherAck(t, health).Status != "healthy" {
		t.Fatalf("health status=%d body=%s", health.Code, health.Body.String())
	}
	stopRequest := SidecarOperationRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: ack.HandleID, Mode: SidecarModeCanary}
	for attempt := 0; attempt < 2; attempt++ {
		stopped := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "stop"), stopRequest)
		if stopped.Code != http.StatusOK || decodeLauncherAck(t, stopped).Status != "stopped" {
			t.Fatalf("stop %d status=%d body=%s", attempt+1, stopped.Code, stopped.Body.String())
		}
	}
	afterStop := callLauncherHandler(t, handler, leaf, true, sidecarRoutePrefix+ack.HandleID+"/health", stopRequest)
	if afterStop.Code != http.StatusGone {
		t.Fatalf("health after stop status=%d, want gone", afterStop.Code)
	}
	modes, probes, stops := process.snapshot()
	if len(modes) != 1 || modes[0] != SidecarModeCanary || probes != 1 || stops != 1 {
		t.Fatalf("backend lifecycle modes=%v probes=%d stops=%d", modes, probes, stops)
	}
	_, consumes := provider.counts()
	if consumes != 0 {
		t.Fatalf("launcher consumed authorization %d times", consumes)
	}
}

func TestSidecarLauncherHandlerRejectsUntrustedAndTamperedRequests(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	otherPKI := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	provider := &launcherProviderFake{}
	backend := &launcherBackendFake{process: &launcherProcessFake{}}
	handler := mustLauncherHandler(t, now, launcherRoots(t, pki.clientBundle.CAPEM), provider, backend)
	request := SidecarStartRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve}

	missingChain := callLauncherHandler(t, handler, leaf, false, sidecarStartPath, request)
	if missingChain.Code != http.StatusUnauthorized {
		t.Fatalf("missing verified chain status=%d", missingChain.Code)
	}
	untrusted := callLauncherHandler(t, handler, otherPKI.clientBundle.Certificate, true, sidecarStartPath, request)
	if untrusted.Code != http.StatusUnauthorized {
		t.Fatalf("untrusted certificate status=%d", untrusted.Code)
	}
	tampered := request
	tampered.Target.Key = "other-plugin"
	if response := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, tampered); response.Code != http.StatusForbidden {
		t.Fatalf("tampered target status=%d", response.Code)
	}

	injectedDescriptor := descriptor
	injectedDescriptor.SourceRoot = "../bin/sh"
	injectedAuthorization := launcherAuthorization(t, now, identity, injectedDescriptor, target)
	injected := SidecarStartRequest{SchemaVersion: TransportSchemaVersion, Authorization: injectedAuthorization, Descriptor: injectedDescriptor, Target: target, Mode: SidecarModeObserve}
	if response := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, injected); response.Code != http.StatusForbidden {
		t.Fatalf("path traversal status=%d", response.Code)
	}

	provider.validateErr = ErrFenceExpired
	if response := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, request); response.Code != http.StatusGone {
		t.Fatalf("stale fence status=%d", response.Code)
	}
	if backend.startCount() != 0 {
		t.Fatalf("rejected requests reached backend: starts=%d", backend.startCount())
	}
}

func TestSidecarLauncherHandlerConcurrentStartRunsBackendOnce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	provider := &launcherProviderFake{}
	backend := &launcherBackendFake{process: &launcherProcessFake{}, started: make(chan struct{}, 1), release: make(chan struct{})}
	handler := mustLauncherHandler(t, now, launcherRoots(t, pki.clientBundle.CAPEM), provider, backend)
	request := SidecarStartRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve}

	const callers = 8
	responses := make(chan int, callers)
	for i := 0; i < callers; i++ {
		go func() {
			responses <- callLauncherHandler(t, handler, leaf, true, sidecarStartPath, request).Code
		}()
	}
	select {
	case <-backend.started:
	case <-time.After(2 * time.Second):
		t.Fatal("backend start was not entered")
	}
	close(backend.release)
	for i := 0; i < callers; i++ {
		if status := <-responses; status != http.StatusOK {
			t.Fatalf("concurrent start status=%d", status)
		}
	}
	if backend.startCount() != 1 {
		t.Fatalf("concurrent backend starts=%d, want 1", backend.startCount())
	}
	_, consumes := provider.counts()
	if consumes != 0 {
		t.Fatalf("concurrent start consumed authorization %d times", consumes)
	}
}

func TestSidecarLauncherHandlerConcurrentStartModeAndStopKeepsStartAcknowledgementObserve(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	process := &launcherProcessFake{}
	backend := &launcherBackendFake{process: process, started: make(chan struct{}, 1), release: make(chan struct{})}
	handler := mustLauncherHandler(t, now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, backend)
	startRequest := SidecarStartRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve}

	startResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		startResult <- callLauncherHandler(t, handler, leaf, true, sidecarStartPath, startRequest)
	}()
	select {
	case <-backend.started:
	case <-time.After(2 * time.Second):
		t.Fatal("backend start was not entered")
	}
	handler.mu.Lock()
	record := handler.byAuthorization[authorization.ID]
	handler.mu.Unlock()
	if record == nil {
		t.Fatal("reserved record is missing")
	}

	modeResult := make(chan *httptest.ResponseRecorder, 1)
	stopResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		modeResult <- callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(record.handle, "mode"), SidecarOperationRequest{
			SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: record.handle, Mode: SidecarModeCanary,
		})
	}()
	go func() {
		stopResult <- callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(record.handle, "stop"), SidecarOperationRequest{
			SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: record.handle, Mode: SidecarModeObserve,
		})
	}()
	close(backend.release)

	start := <-startResult
	if start.Code != http.StatusOK || decodeLauncherAck(t, start).Mode != SidecarModeObserve {
		t.Fatalf("start status=%d acknowledgement=%s", start.Code, start.Body.String())
	}
	modeResponse := <-modeResult
	if modeResponse.Code != http.StatusOK && modeResponse.Code != http.StatusConflict {
		t.Fatalf("concurrent mode status=%d", modeResponse.Code)
	}
	stop := <-stopResult
	if stop.Code != http.StatusOK && stop.Code != http.StatusConflict {
		t.Fatalf("concurrent stop status=%d", stop.Code)
	}
	if stop.Code == http.StatusConflict {
		currentMode := SidecarModeObserve
		if modeResponse.Code == http.StatusOK {
			currentMode = SidecarModeCanary
		}
		stopped := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(record.handle, "stop"), SidecarOperationRequest{
			SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: record.handle, Mode: currentMode,
		})
		if stopped.Code != http.StatusOK {
			t.Fatalf("serialized stop status=%d", stopped.Code)
		}
	}
	modes, probes, stops := process.snapshot()
	if len(modes) > 1 || probes != 0 || stops != 1 {
		t.Fatalf("concurrent lifecycle modes=%v probes=%d stops=%d", modes, probes, stops)
	}
}

func TestSidecarLauncherRecordCompleteStartSnapshotsObserveBeforeReady(t *testing.T) {
	record := &sidecarLauncherRecord{
		handle: "sidecar-test", authorization: Authorization{ID: "authorization", Request: AuthorizationRequest{RequestID: "request", Identity: TransportIdentity{NodeID: "node"}}},
		target: RuntimeTarget{Key: "plugin", ManifestIdentity: "manifest"}, ready: make(chan struct{}), mode: SidecarModeObserve,
	}
	transitioned := make(chan struct{})
	go func() {
		<-record.ready
		record.mu.Lock()
		record.mode = SidecarModeCanary
		record.mu.Unlock()
		close(transitioned)
	}()

	acknowledgement := record.completeStart(&launcherProcessFake{}, nil)
	<-transitioned
	if acknowledgement.Mode != SidecarModeObserve {
		t.Fatalf("start acknowledgement mode=%q, want observe", acknowledgement.Mode)
	}
}

func TestSidecarLauncherHandlerRejectsExpiredTrafficOperationsAndReaps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := &launcherClock{now: now}
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	process := &launcherProcessFake{}
	backend := &launcherBackendFake{process: process}
	handler := mustLauncherHandlerWithOptions(t, clock.Now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, backend, 1)
	start := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	ack := decodeLauncherAck(t, start)
	clock.Set(authorization.ExpiresAt)

	for _, operation := range []string{"mode", "probe", "health"} {
		response := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, operation), SidecarOperationRequest{
			SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: ack.HandleID, Mode: SidecarModeCanary,
		})
		if response.Code != http.StatusGone {
			t.Fatalf("expired %s status=%d, want gone", operation, response.Code)
		}
	}
	modes, probes, stops := process.snapshot()
	if len(modes) != 0 || probes != 0 || stops != 1 {
		t.Fatalf("expired lifecycle modes=%v probes=%d stops=%d", modes, probes, stops)
	}
	if handler.lookup(ack.HandleID) != nil {
		t.Fatal("reaped sidecar record remains addressable")
	}
}

func TestSidecarLauncherHandlerAllowsExactHistoricalStopAfterExpiryAndFreesSlot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := &launcherClock{now: now}
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	process := &launcherProcessFake{}
	backend := &launcherBackendFake{process: process}
	handler := mustLauncherHandlerWithOptions(t, clock.Now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, backend, 1)
	start := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	ack := decodeLauncherAck(t, start)
	clock.Set(authorization.ExpiresAt)

	forged := cloneAuthorization(authorization)
	forged.ID = "forged-authorization"
	forgedStop := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "stop"), SidecarOperationRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: forged, HandleID: ack.HandleID, Mode: SidecarModeObserve,
	})
	if forgedStop.Code != http.StatusForbidden {
		t.Fatalf("forged historical stop status=%d, want forbidden", forgedStop.Code)
	}
	if _, _, stops := process.snapshot(); stops != 0 {
		t.Fatalf("forged historical stop reached backend: stops=%d", stops)
	}
	crossIdentity := cloneAuthorization(authorization)
	crossIdentity.Request.Identity.NodeID = "node-b"
	crossIdentityStop := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "stop"), SidecarOperationRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: crossIdentity, HandleID: ack.HandleID, Mode: SidecarModeObserve,
	})
	if crossIdentityStop.Code != http.StatusForbidden {
		t.Fatalf("cross-identity historical stop status=%d, want forbidden", crossIdentityStop.Code)
	}
	if _, _, stops := process.snapshot(); stops != 0 {
		t.Fatalf("cross-identity historical stop reached backend: stops=%d", stops)
	}

	stopRequest := SidecarOperationRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: ack.HandleID, Mode: SidecarModeObserve}
	for attempt := 0; attempt < 2; attempt++ {
		stopped := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "stop"), stopRequest)
		if stopped.Code != http.StatusOK || decodeLauncherAck(t, stopped).Status != "stopped" {
			t.Fatalf("historical stop %d status=%d body=%s", attempt+1, stopped.Code, stopped.Body.String())
		}
	}
	if _, _, stops := process.snapshot(); stops != 1 {
		t.Fatalf("historical stop backend calls=%d, want 1", stops)
	}

	fresh := launcherAuthorization(t, clock.Now(), identity, descriptor, target)
	fresh.ID = "launcher-auth-2"
	replacement := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: fresh, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	if replacement.Code != http.StatusOK {
		t.Fatalf("replacement start status=%d", replacement.Code)
	}
	if backend.startCount() != 2 {
		t.Fatalf("backend starts=%d, want expired slot to be reused", backend.startCount())
	}
}

func TestSidecarLauncherHandlerRetainsExpiredSlotWhenReaperStopFails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := &launcherClock{now: now}
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	process := &launcherProcessFake{stopErr: errors.New("ambiguous runtime stop")}
	backend := &launcherBackendFake{process: process}
	handler := mustLauncherHandlerWithOptions(t, clock.Now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, backend, 1)
	start := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	ack := decodeLauncherAck(t, start)
	clock.Set(authorization.ExpiresAt)

	response := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "probe"), SidecarOperationRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: ack.HandleID, Mode: SidecarModeObserve,
	})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired reaper failure status=%d, want service unavailable", response.Code)
	}
	fresh := launcherAuthorization(t, clock.Now(), identity, descriptor, target)
	fresh.ID = "launcher-auth-2"
	replacement := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: fresh, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	if replacement.Code != http.StatusServiceUnavailable {
		t.Fatalf("start after ambiguous reaper stop status=%d, want service unavailable", replacement.Code)
	}
	_, probes, stops := process.snapshot()
	if probes != 0 || stops != 1 {
		t.Fatalf("failed reaper backend probes=%d stops=%d", probes, stops)
	}
	if handler.lookup(ack.HandleID) == nil {
		t.Fatal("record was released after ambiguous stop")
	}
	if backend.startCount() != 1 {
		t.Fatalf("backend starts=%d, want retained slot to prevent replacement", backend.startCount())
	}
}

func TestSidecarLauncherHandlerReapsStartThatExpiresDuringLaunch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := &launcherClock{now: now}
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	process := &launcherProcessFake{}
	backend := &launcherBackendFake{process: process, started: make(chan struct{}, 1), release: make(chan struct{})}
	handler := mustLauncherHandlerWithOptions(t, clock.Now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, backend, 1)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
			SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
		})
	}()
	select {
	case <-backend.started:
	case <-time.After(2 * time.Second):
		t.Fatal("backend start was not entered")
	}
	clock.Set(authorization.ExpiresAt)
	close(backend.release)
	if response := <-result; response.Code != http.StatusGone {
		t.Fatalf("expired start completion status=%d, want gone", response.Code)
	}
	_, _, stops := process.snapshot()
	if stops != 1 {
		t.Fatalf("expired start process stops=%d, want 1", stops)
	}
	handler.mu.Lock()
	remaining := len(handler.byHandle)
	handler.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expired start records=%d, want 0", remaining)
	}
}

func TestSidecarLauncherHandlerBackendErrorsFailClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	backend := &launcherBackendFake{startErr: errors.New("runtime unavailable")}
	handler := mustLauncherHandler(t, now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, backend)
	request := SidecarStartRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, Descriptor: descriptor, Target: target, Mode: SidecarModeObserve}
	first := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, request)
	second := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, request)
	if first.Code != http.StatusServiceUnavailable || second.Code != http.StatusServiceUnavailable {
		t.Fatalf("backend errors statuses=%d,%d", first.Code, second.Code)
	}
	if backend.startCount() != 1 {
		t.Fatalf("ambiguous backend start retried: starts=%d", backend.startCount())
	}
}

func TestSidecarLauncherHandlerStopFailureIsNotRetriedOrTreatedHealthy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newMTLSPKIFixture(t)
	leaf := pki.clientBundle.Certificate
	identity := certificateTransportIdentity(leaf, "cluster-a", "node-a", "waf")
	descriptor := launcherDescriptor()
	target := runtimeTarget(launcherRecord(descriptor))
	authorization := launcherAuthorization(t, now, identity, descriptor, target)
	process := &launcherProcessFake{stopErr: errors.New("ambiguous runtime stop")}
	handler := mustLauncherHandler(t, now, launcherRoots(t, pki.clientBundle.CAPEM), &launcherProviderFake{}, &launcherBackendFake{process: process})
	start := callLauncherHandler(t, handler, leaf, true, sidecarStartPath, SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization,
		Descriptor: descriptor, Target: target, Mode: SidecarModeObserve,
	})
	ack := decodeLauncherAck(t, start)
	request := SidecarOperationRequest{SchemaVersion: TransportSchemaVersion, Authorization: authorization, HandleID: ack.HandleID, Mode: SidecarModeObserve}
	for attempt := 0; attempt < 2; attempt++ {
		response := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "stop"), request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("failed stop %d status=%d", attempt+1, response.Code)
		}
	}
	health := callLauncherHandler(t, handler, leaf, true, sidecarOperationPath(ack.HandleID, "probe"), request)
	if health.Code != http.StatusConflict {
		t.Fatalf("health after ambiguous stop status=%d, want conflict", health.Code)
	}
	_, probes, stops := process.snapshot()
	if probes != 0 || stops != 1 {
		t.Fatalf("ambiguous stop backend probes=%d stops=%d", probes, stops)
	}
}

func mustLauncherHandler(t *testing.T, now time.Time, roots *x509.CertPool, provider AuthorizationProvider, backend SidecarLauncherBackend) *SidecarLauncherHandler {
	t.Helper()
	return mustLauncherHandlerWithOptions(t, func() time.Time { return now }, roots, provider, backend, 0)
}

func mustLauncherHandlerWithOptions(t *testing.T, clock func() time.Time, roots *x509.CertPool, provider AuthorizationProvider, backend SidecarLauncherBackend, maxSlots int) *SidecarLauncherHandler {
	t.Helper()
	handler, err := NewSidecarLauncherHandler(SidecarLauncherHandlerOptions{
		ClusterID: "cluster-a", ClientCA: roots, Clock: clock,
		Provider: provider, Backend: backend, MaxSlots: maxSlots,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func launcherRoots(t *testing.T, pem []byte) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("failed to parse launcher CA")
	}
	return roots
}

func launcherDescriptor() SidecarDescriptor {
	return SidecarDescriptor{
		PluginID: "rate-limit", Runtime: "sidecar", Version: "1.0.0",
		Namespace: "official/security", Source: "ota", SourceRoot: "root",
		ManifestIdentity: strings.Repeat("a", 64), ArtifactIdentity: strings.Repeat("b", 64),
		Capabilities: []string{"observe"},
	}
}

func launcherRecord(descriptor SidecarDescriptor) crp.RuntimeRecord {
	return crp.RuntimeRecord{
		Key: "rate-limit", PluginID: descriptor.PluginID, Namespace: descriptor.Namespace,
		Version: descriptor.Version, ReleaseSequence: 1,
		ManifestIdentity: descriptor.ManifestIdentity, ArtifactIdentity: descriptor.ArtifactIdentity,
		Revision: 1,
	}
}

func launcherAuthorization(t *testing.T, now time.Time, identity TransportIdentity, descriptor SidecarDescriptor, target RuntimeTarget) Authorization {
	t.Helper()
	digest, err := descriptorIdentity(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{
		SchemaVersion: TransportSchemaVersion, RequestID: "launcher-request-1", Identity: identity,
		Action: crp.RuntimeActionPromote, Permission: PermissionActivate,
		Target: target, ExpectedRevision: target.Revision,
		Descriptor: descriptor, DescriptorIdentity: digest,
		Canary: CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1}, RequestedAt: now,
	}
	request.ApprovalClaim = testApprovalClaim(request)
	expires := now.Add(time.Minute)
	return Authorization{
		SchemaVersion: TransportSchemaVersion, ID: "launcher-auth-1", Request: request,
		ApprovalClaim: request.ApprovalClaim,
		Fence:         Fence{ClusterID: identity.ClusterID, Token: "launcher-fence-1", Epoch: 1, Revision: 1, ExpiresAt: expires},
		Confirmation: &WireConfirmation{
			ID: request.ApprovalClaim.ConfirmationID, Actor: request.ApprovalClaim.Actor,
			Action: request.Action, PluginKey: target.Key, ManifestIdentity: target.ManifestIdentity,
			ExpectedRevision: request.ExpectedRevision, AuthorizedAt: now, ExpiresAt: expires,
		},
		IssuedAt: now, ExpiresAt: expires,
	}
}

func callLauncherHandler(t *testing.T, handler http.Handler, leaf *x509.Certificate, verified bool, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CheeseWAF-Transport-Schema", TransportSchemaVersion)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if verified {
		request.TLS.VerifiedChains = [][]*x509.Certificate{{leaf}}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeLauncherAck(t *testing.T, recorder *httptest.ResponseRecorder) SidecarAcknowledgement {
	t.Helper()
	var acknowledgement SidecarAcknowledgement
	if err := json.Unmarshal(recorder.Body.Bytes(), &acknowledgement); err != nil {
		t.Fatal(err)
	}
	return acknowledgement
}
