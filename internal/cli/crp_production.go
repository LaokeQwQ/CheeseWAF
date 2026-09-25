package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	activationpostgres "github.com/LaokeQwQ/CheeseWAF/internal/crp/activation/postgres"
)

const (
	EnvProductionCRPListenEndpoint        = "CHEESEWAF_CRP_LISTEN_ENDPOINT"
	EnvProductionCRPSidecarListenEndpoint = "CHEESEWAF_CRP_SIDECAR_LISTEN_ENDPOINT"
	EnvProductionCRPControlEndpoint       = "CHEESEWAF_CRP_CONTROL_ENDPOINT"
	EnvProductionCRPSidecarEndpoint       = "CHEESEWAF_CRP_SIDECAR_ENDPOINT"
	EnvProductionCRPSidecarRegistryFile   = "CHEESEWAF_CRP_SIDECAR_REGISTRY_FILE"
	EnvProductionCRPCAFile                = "CHEESEWAF_CRP_CA_FILE"
	EnvProductionCRPServerCertFile        = "CHEESEWAF_CRP_SERVER_CERT_FILE"
	EnvProductionCRPServerKeyFile         = "CHEESEWAF_CRP_SERVER_KEY_FILE"
	EnvProductionCRPClientCertFile        = "CHEESEWAF_CRP_CLIENT_CERT_FILE"
	EnvProductionCRPClientKeyFile         = "CHEESEWAF_CRP_CLIENT_KEY_FILE"
	EnvProductionCRPControlServerName     = "CHEESEWAF_CRP_CONTROL_SERVER_NAME"
	EnvProductionCRPSidecarServerName     = "CHEESEWAF_CRP_SIDECAR_SERVER_NAME"
	defaultProductionCRPTransportTimeout  = 15 * time.Second
	defaultProductionCRPReadHeaderTimeout = 10 * time.Second
)

var (
	ErrProductionCRPUnavailable = errors.New("production CRP composition is unavailable")
	ErrProductionCRPConfig      = errors.New("production CRP runtime configuration is invalid")
	ErrProductionCRPLifecycle   = errors.New("production CRP lifecycle is invalid")
)

// ProductionCRPOptions is runtime-only process configuration. The paths and
// endpoints are intentionally not derived from the tracked YAML template.
// Runtime, Provider, State, Audit and FenceSource are opened by the owning
// production launcher and are never replaced with process-local fallbacks.
type ProductionCRPOptions struct {
	ListenEndpoint        string
	SidecarListenEndpoint string
	ControlEndpoint       string
	SidecarEndpoint       string
	CAFile                string
	ServerCertFile        string
	ServerKeyFile         string
	ClientCertFile        string
	ClientKeyFile         string
	ControlServerName     string
	SidecarServerName     string
	SidecarRegistryFile   string

	ClusterID        string
	NodeID           string
	TransportTimeout time.Duration

	Runtime               *crp.RuntimeStore
	State                 activation.AuthorizationState
	Provider              activation.AuthorizationProvider
	Audit                 activation.DurableAuthorizationAudit
	FenceSource           activationpostgres.FenceSource
	SidecarBackend        activation.SidecarLauncherBackend
	SidecarMaxSlots       int
	ApprovalClaimResolver activation.ApprovalClaimResolver
	Policy                activation.Policy
	Clock                 func() time.Time
	AsyncQueueSize        int
	AsyncWorkers          int
	OperationTimeout      time.Duration
}

// ProductionCRPOptionsFromEnvironment fills only unset transport fields from
// the process environment. Explicit launcher options always win. Values are
// preserved byte-for-byte so leading/trailing or invisible whitespace is
// rejected later rather than silently normalized into another identity.
func ProductionCRPOptionsFromEnvironment(opts ProductionCRPOptions) ProductionCRPOptions {
	return productionCRPOptionsFromLookup(opts, os.LookupEnv)
}

func productionCRPOptionsFromLookup(opts ProductionCRPOptions, lookup func(string) (string, bool)) ProductionCRPOptions {
	if lookup == nil {
		return opts
	}
	fill := func(target *string, name string) {
		if *target != "" {
			return
		}
		if value, ok := lookup(name); ok {
			*target = value
		}
	}
	fill(&opts.ListenEndpoint, EnvProductionCRPListenEndpoint)
	fill(&opts.SidecarListenEndpoint, EnvProductionCRPSidecarListenEndpoint)
	fill(&opts.ControlEndpoint, EnvProductionCRPControlEndpoint)
	fill(&opts.SidecarEndpoint, EnvProductionCRPSidecarEndpoint)
	fill(&opts.CAFile, EnvProductionCRPCAFile)
	fill(&opts.ServerCertFile, EnvProductionCRPServerCertFile)
	fill(&opts.ServerKeyFile, EnvProductionCRPServerKeyFile)
	fill(&opts.ClientCertFile, EnvProductionCRPClientCertFile)
	fill(&opts.ClientKeyFile, EnvProductionCRPClientKeyFile)
	fill(&opts.ControlServerName, EnvProductionCRPControlServerName)
	fill(&opts.SidecarServerName, EnvProductionCRPSidecarServerName)
	fill(&opts.SidecarRegistryFile, EnvProductionCRPSidecarRegistryFile)
	return opts
}

// ProductionCRP owns the production CRP handler, outbound mTLS adapters,
// activation service and authorization listener. Runtime and fence source
// lifetimes remain owned by the caller so the same durable runtime can be
// shared with CWEDP without opening a second store.
type ProductionCRP struct {
	handler          *activation.ControlPlaneHandler
	sidecarHandler   *activation.SidecarLauncherHandler
	controlPlane     *activation.HTTPControlPlaneClient
	sidecars         *activation.HTTPSidecarManager
	service          *activation.Service
	runtime          *crp.RuntimeStore
	server           *http.Server
	listener         net.Listener
	tlsConfig        *tls.Config
	sidecarServer    *http.Server
	sidecarListener  net.Listener
	sidecarTLSConfig *tls.Config
	endpoint         string
	sidecarEndpoint  string
	fenceSource      activationpostgres.FenceSource

	mu       sync.Mutex
	started  bool
	closed   bool
	serveErr error
	done     chan struct{}
	serveWG  sync.WaitGroup
	doneOnce sync.Once
	stopOnce sync.Once
	stopErr  error
}

// OpenProductionCRP constructs the complete production bundle without
// starting its listener. Call Start after the owning serve lifecycle is ready.
// Every authority-bearing dependency and every TLS endpoint must be supplied
// explicitly; no CA, certificate, fence, provider, sidecar or runtime is
// synthesized here.
func OpenProductionCRP(ctx context.Context, opts ProductionCRPOptions) (*ProductionCRP, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opts = ProductionCRPOptionsFromEnvironment(opts)
	if err := validateProductionCRPOptions(opts); err != nil {
		return nil, err
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.TransportTimeout == 0 {
		opts.TransportTimeout = defaultProductionCRPTransportTimeout
	}

	serverTLS, err := activation.NewControlPlaneServerTLSConfig(activation.ServerTLSOptions{
		CAFile: opts.CAFile, CertFile: opts.ServerCertFile, KeyFile: opts.ServerKeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: control-plane server TLS: %v", ErrProductionCRPConfig, err)
	}
	handler, err := activation.NewProductionControlPlaneHandler(activation.ProductionControlPlaneHandlerOptions{
		ClusterID: opts.ClusterID,
		ClientCA:  serverTLS.ClientCAs,
		State:     opts.State,
		Provider:  opts.Provider,
		Audit:     opts.Audit,
		Clock:     opts.Clock,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: control-plane handler: %v", ErrProductionCRPUnavailable, err)
	}
	sidecarHandler, err := activation.NewSidecarLauncherHandler(activation.SidecarLauncherHandlerOptions{
		ClusterID: opts.ClusterID,
		Role:      "waf",
		ClientCA:  serverTLS.ClientCAs,
		Clock:     opts.Clock,
		Provider:  opts.Provider,
		Backend:   opts.SidecarBackend,
		MaxSlots:  opts.SidecarMaxSlots,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: sidecar launcher handler: %v", ErrProductionCRPUnavailable, err)
	}

	clientOptions := activation.MTLSOptions{
		CAFile: opts.CAFile, CertFile: opts.ClientCertFile, KeyFile: opts.ClientKeyFile,
		ClusterID: opts.ClusterID, NodeID: opts.NodeID, Role: "waf",
		ServerName: opts.ControlServerName, Timeout: opts.TransportTimeout,
	}
	controlTransport, err := activation.NewMTLSClient(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: control-plane client TLS: %v", ErrProductionCRPConfig, err)
	}
	controlPlane, err := activation.NewHTTPControlPlaneClient(opts.ControlEndpoint, controlTransport, opts.Clock)
	if err != nil {
		return nil, fmt.Errorf("%w: control-plane client: %v", ErrProductionCRPConfig, err)
	}
	runtimeAuthorizer, err := activation.NewRuntimeAuthorizer(controlPlane)
	if err != nil {
		return nil, fmt.Errorf("%w: runtime authorizer: %v", ErrProductionCRPConfig, err)
	}
	clientOptions.ServerName = opts.SidecarServerName
	sidecarTransport, err := activation.NewMTLSClient(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: sidecar client TLS: %v", ErrProductionCRPConfig, err)
	}
	sidecars, err := activation.NewHTTPSidecarManager(opts.SidecarEndpoint, sidecarTransport, opts.Clock)
	if err != nil {
		return nil, fmt.Errorf("%w: sidecar client: %v", ErrProductionCRPConfig, err)
	}
	service, err := activation.NewService(opts.Runtime, activation.Options{
		Sidecars:              sidecars,
		ControlPlane:          controlPlane,
		ApprovalClaimResolver: opts.ApprovalClaimResolver,
		Policy:                opts.Policy,
		Clock:                 opts.Clock,
		AsyncQueueSize:        opts.AsyncQueueSize,
		AsyncWorkers:          opts.AsyncWorkers,
		OperationTimeout:      opts.OperationTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: activation service: %v", ErrProductionCRPUnavailable, err)
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.ListenEndpoint)
	if err != nil {
		_ = service.CloseAsync()
		return nil, fmt.Errorf("%w: listen on %q: %v", ErrProductionCRPUnavailable, opts.ListenEndpoint, err)
	}
	sidecarListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.SidecarListenEndpoint)
	if err != nil {
		_ = listener.Close()
		_ = service.CloseAsync()
		return nil, fmt.Errorf("%w: sidecar listen on %q: %v", ErrProductionCRPUnavailable, opts.SidecarListenEndpoint, err)
	}
	// Bind the one-shot runtime authorizer only after every other fallible
	// component has been constructed. The RuntimeStore is shared with CWEDP;
	// poisoning it on a failed CRP startup attempt would make a corrected
	// configuration impossible to retry in the same process.
	if err := opts.Runtime.BindAuthorizer(runtimeAuthorizer); err != nil {
		_ = sidecarListener.Close()
		_ = listener.Close()
		_ = service.CloseAsync()
		return nil, fmt.Errorf("%w: bind shared runtime authorizer: %v", ErrProductionCRPUnavailable, err)
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: defaultProductionCRPReadHeaderTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	sidecarServer := &http.Server{
		Handler:           sidecarHandler,
		TLSConfig:         serverTLS.Clone(),
		ReadHeaderTimeout: defaultProductionCRPReadHeaderTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return &ProductionCRP{
		handler: handler, sidecarHandler: sidecarHandler,
		controlPlane: controlPlane, sidecars: sidecars, service: service, runtime: opts.Runtime,
		server: server, listener: listener, tlsConfig: serverTLS,
		sidecarServer: sidecarServer, sidecarListener: sidecarListener, sidecarTLSConfig: sidecarServer.TLSConfig,
		endpoint: "https://" + listener.Addr().String(), sidecarEndpoint: "https://" + sidecarListener.Addr().String(), fenceSource: opts.FenceSource,
		done: make(chan struct{}),
	}, nil
}

func validateProductionCRPOptions(opts ProductionCRPOptions) error {
	required := map[string]string{
		"listen endpoint": opts.ListenEndpoint, "sidecar listen endpoint": opts.SidecarListenEndpoint,
		"control endpoint": opts.ControlEndpoint,
		"sidecar endpoint": opts.SidecarEndpoint, "CA file": opts.CAFile,
		"server certificate": opts.ServerCertFile, "server key": opts.ServerKeyFile,
		"client certificate": opts.ClientCertFile, "client key": opts.ClientKeyFile,
		"control server name": opts.ControlServerName, "sidecar server name": opts.SidecarServerName,
		"cluster ID": opts.ClusterID, "node ID": opts.NodeID,
	}
	for name, value := range required {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%w: %s is required without surrounding whitespace", ErrProductionCRPConfig, name)
		}
	}
	if _, _, err := net.SplitHostPort(opts.ListenEndpoint); err != nil {
		return fmt.Errorf("%w: listen endpoint must be host:port: %v", ErrProductionCRPConfig, err)
	}
	if _, _, err := net.SplitHostPort(opts.SidecarListenEndpoint); err != nil {
		return fmt.Errorf("%w: sidecar listen endpoint must be host:port: %v", ErrProductionCRPConfig, err)
	}
	if opts.SidecarListenEndpoint == opts.ListenEndpoint {
		return fmt.Errorf("%w: control-plane and sidecar listeners must use distinct endpoints", ErrProductionCRPConfig)
	}
	if opts.TransportTimeout != 0 && (opts.TransportTimeout < time.Second || opts.TransportTimeout > time.Minute) {
		return fmt.Errorf("%w: transport timeout must be between 1s and 1m", ErrProductionCRPConfig)
	}
	if opts.Runtime == nil || isNilProductionCRPDependency(opts.State) || isNilProductionCRPDependency(opts.Provider) ||
		isNilProductionCRPDependency(opts.Audit) || isNilProductionCRPDependency(opts.FenceSource) || isNilProductionCRPDependency(opts.SidecarBackend) {
		return fmt.Errorf("%w: runtime, durable state/provider/audit, fence source and sidecar backend are required", ErrProductionCRPUnavailable)
	}
	if opts.ApprovalClaimResolver == nil {
		return fmt.Errorf("%w: approval claim resolver is required", ErrProductionCRPUnavailable)
	}
	if opts.Policy.VerifyRecord == nil {
		return fmt.Errorf("%w: fresh runtime verification policy is required", ErrProductionCRPUnavailable)
	}
	return nil
}

func isNilProductionCRPDependency(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// Start begins serving TLS 1.3 with mandatory verified client certificates.
// The listener is opened during construction so bind failures happen before
// the owning process reports readiness.
func (p *ProductionCRP) Start() error {
	if p == nil || p.server == nil || p.listener == nil || p.tlsConfig == nil ||
		p.sidecarServer == nil || p.sidecarListener == nil || p.sidecarTLSConfig == nil {
		return ErrProductionCRPLifecycle
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return fmt.Errorf("%w: bundle is closed", ErrProductionCRPLifecycle)
	}
	if p.started {
		return fmt.Errorf("%w: bundle is already started", ErrProductionCRPLifecycle)
	}
	p.started = true
	p.serveWG.Add(2)
	go p.serve("control-plane", p.server, p.listener, p.tlsConfig)
	go p.serve("sidecar", p.sidecarServer, p.sidecarListener, p.sidecarTLSConfig)
	go func() {
		p.serveWG.Wait()
		p.doneOnce.Do(func() { close(p.done) })
	}()
	return nil
}

func (p *ProductionCRP) serve(name string, server *http.Server, listener net.Listener, tlsConfig *tls.Config) {
	defer p.serveWG.Done()
	err := server.Serve(tls.NewListener(listener, tlsConfig))
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	p.mu.Lock()
	planned := p.closed
	if !planned && err == nil {
		err = fmt.Errorf("%w: %s listener exited unexpectedly", ErrProductionCRPLifecycle, name)
	}
	if err != nil && p.serveErr == nil {
		p.serveErr = fmt.Errorf("%s listener: %w", name, err)
	}
	p.mu.Unlock()
	if !planned {
		_ = p.server.Close()
		_ = p.sidecarServer.Close()
		_ = p.listener.Close()
		_ = p.sidecarListener.Close()
	}
}

// Wait blocks until the listener exits or the supplied context is canceled.
func (p *ProductionCRP) Wait(ctx context.Context) error {
	if p == nil {
		return ErrProductionCRPLifecycle
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	started := p.started
	done := p.done
	p.mu.Unlock()
	if !started {
		return fmt.Errorf("%w: bundle is not started", ErrProductionCRPLifecycle)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.serveErr
	}
}

// Shutdown gracefully stops admission, then closes the activation worker and
// all sidecars it owns. It does not close the shared RuntimeStore or fence
// source, whose lifetime belongs to the main production dependency graph.
func (p *ProductionCRP) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		started := p.started
		p.mu.Unlock()
		// Stop new control-plane admissions first, but keep the sidecar
		// launcher reachable until Service.CloseAsync has stopped every
		// process it owns. Closing both listeners first makes the service's
		// authenticated Stop calls fail over their own production transport.
		if started {
			p.stopErr = joinProductionCRPCloseError(p.stopErr, p.server.Shutdown(ctx))
		} else {
			p.stopErr = joinProductionCRPCloseError(p.stopErr, p.listener.Close())
		}
		p.stopErr = joinProductionCRPCloseError(p.stopErr, p.service.CloseAsync())
		if started {
			p.stopErr = joinProductionCRPCloseError(p.stopErr, p.sidecarServer.Shutdown(ctx))
			p.stopErr = joinProductionCRPCloseError(p.stopErr, p.listener.Close())
			p.stopErr = joinProductionCRPCloseError(p.stopErr, p.sidecarListener.Close())
		} else {
			p.stopErr = joinProductionCRPCloseError(p.stopErr, p.sidecarListener.Close())
		}
	})
	return p.stopErr
}

// Close immediately terminates the listener and then releases service-owned
// workers and sidecars. It is idempotent and safe after Shutdown.
func (p *ProductionCRP) Close() error {
	if p == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		p.stopErr = joinProductionCRPCloseError(p.stopErr, p.server.Close())
		p.stopErr = joinProductionCRPCloseError(p.stopErr, p.listener.Close())
		p.stopErr = joinProductionCRPCloseError(p.stopErr, p.service.CloseAsync())
		p.stopErr = joinProductionCRPCloseError(p.stopErr, p.sidecarServer.Close())
		p.stopErr = joinProductionCRPCloseError(p.stopErr, p.sidecarListener.Close())
	})
	return p.stopErr
}

func joinProductionCRPCloseError(current, err error) error {
	if err == nil {
		return current
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return current
	}
	return errors.Join(current, err)
}

func (p *ProductionCRP) Endpoint() string {
	if p == nil {
		return ""
	}
	return p.endpoint
}

func (p *ProductionCRP) SidecarEndpoint() string {
	if p == nil {
		return ""
	}
	return p.sidecarEndpoint
}

func (p *ProductionCRP) Handler() *activation.ControlPlaneHandler {
	if p == nil {
		return nil
	}
	return p.handler
}

func (p *ProductionCRP) SidecarHandler() *activation.SidecarLauncherHandler {
	if p == nil {
		return nil
	}
	return p.sidecarHandler
}

func (p *ProductionCRP) ControlPlane() *activation.HTTPControlPlaneClient {
	if p == nil {
		return nil
	}
	return p.controlPlane
}

func (p *ProductionCRP) Sidecars() *activation.HTTPSidecarManager {
	if p == nil {
		return nil
	}
	return p.sidecars
}

func (p *ProductionCRP) Service() *activation.Service {
	if p == nil {
		return nil
	}
	return p.service
}

// Runtime returns the caller-owned runtime instance used by Service. It is
// exposed so the main serve composition can prove it is sharing the exact
// CWEDP runtime rather than opening a second state directory.
func (p *ProductionCRP) Runtime() *crp.RuntimeStore {
	if p == nil {
		return nil
	}
	return p.runtime
}
