// Package consumer composes the CWEDP protocol, transport, durable resume
// store, and CRP staging boundary for one management-plane request.
package consumer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

var (
	ErrUnavailable = errors.New("CWEDP production consumer is unavailable")
	ErrRequest     = errors.New("invalid CWEDP production download request")
)

// Request intentionally contains the authenticated identity and the fresh
// password proof separately from untrusted transfer data. HTTP controllers
// must obtain Identity from server-side session claims, never the request body.
type Request struct {
	Identity     netlease.AdministratorIdentity
	Password     string
	Intent       cwedp.DistributionIntent
	Hello        cwedp.Hello
	Capabilities cwedp.Capabilities
	PolicyEpoch  uint64
	TTL          time.Duration
	MaxBytes     int64
}

type Result struct {
	JobID  string
	Source cwedp.Source
	Staged crp.RuntimeRecord
}

type Executor interface {
	DownloadCWEDP(context.Context, Request) (Result, error)
}

// DurableResumeStore is the marker production composition uses to prevent an
// in-memory AtomicResumeStore from being passed off as restart-safe state.
// The PostgreSQL adapter implements it; contract tests may provide a small
// marker implementation without opening a database.
type DurableResumeStore interface {
	cwedp.AtomicResumeStore
	DurableCWEDPResumeStore()
}

// AdapterFactory receives the exact registered endpoint selected by the
// transport and must mint a fresh request-scoped LeaseBoundAdapter. It must
// not return a reusable HTTP client or an adapter retained from startup.
type AdapterFactory func(context.Context, Request, transport.Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (transport.LeaseBoundAdapter, error)

type Options struct {
	ResumeStore           DurableResumeStore
	Registry              transport.Registry
	IntentVerifier        cwedp.IntentSignatureVerifier
	CRPImportOptions      crp.ImportOptions
	Runtime               *crp.RuntimeStore
	AdapterFactory        AdapterFactory
	PolicyEpoch           uint64
	MinIndependentSources int
	Now                   func() time.Time
}

type Service struct {
	resumeStore      DurableResumeStore
	registry         transport.Registry
	intentVerifier   cwedp.IntentSignatureVerifier
	crpImportOptions crp.ImportOptions
	runtime          *crp.RuntimeStore
	adapterFactory   AdapterFactory
	policyEpoch      uint64
	minSources       int
	now              func() time.Time
}

// New constructs only a fully durable staged-download consumer. In-memory
// resume state is deliberately not accepted here: management downloads may
// resume across process restarts and must never masquerade as production.
func New(opts Options) (*Service, error) {
	if opts.ResumeStore == nil || opts.IntentVerifier == nil || opts.Runtime == nil || opts.AdapterFactory == nil || opts.PolicyEpoch == 0 {
		return nil, ErrUnavailable
	}
	endpoints := opts.Registry.Endpoints()
	if len(endpoints) == 0 {
		return nil, ErrUnavailable
	}
	for _, endpoint := range endpoints {
		if endpoint.Source.Kind != cwedp.SourceOffline && endpoint.Adapter != nil {
			// Puller prefers Endpoint.Adapter over AdapterProvider. Rejecting it
			// here prevents a startup-retained adapter from bypassing the fresh
			// management confirmation path.
			return nil, fmt.Errorf("%w: online registry endpoint has a static adapter", ErrUnavailable)
		}
	}
	minSources := opts.MinIndependentSources
	if minSources < 1 || minSources > 2 {
		return nil, fmt.Errorf("%w: minimum independent sources", ErrUnavailable)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{
		resumeStore:      opts.ResumeStore,
		registry:         opts.Registry,
		intentVerifier:   opts.IntentVerifier,
		crpImportOptions: opts.CRPImportOptions,
		runtime:          opts.Runtime,
		adapterFactory:   opts.AdapterFactory,
		policyEpoch:      opts.PolicyEpoch,
		minSources:       minSources,
		now:              opts.Now,
	}, nil
}

func (s *Service) DownloadCWEDP(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.resumeStore == nil || s.runtime == nil || s.adapterFactory == nil || s.intentVerifier == nil {
		return Result{}, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateRequest(req, s.policyEpoch); err != nil {
		return Result{}, err
	}
	if err := s.registry.AuthorizeIntent(req.Intent); err != nil {
		return Result{}, err
	}
	selected, err := cwedp.Negotiate(req.Intent, req.Hello, req.Capabilities)
	if err != nil {
		return Result{}, err
	}
	endpoint, ok := s.registry.Endpoint(selected)
	if !ok {
		return Result{}, transport.ErrUnauthorizedSource
	}
	binding, err := leaseBinding(req, endpoint)
	if err != nil {
		return Result{}, err
	}
	broker := cwedp.NewBroker(cwedp.BrokerConfig{
		Registry:              s.registry.ProtocolRegistry(),
		ResumeStore:           s.resumeStore,
		LeaseVerifier:         exactLeaseVerifier{want: binding},
		MinIndependentSources: s.minSources,
		MaxArtifactBytes:      cwedp.DefaultMaxArtifactBytes,
		MaxChunkBytes:         cwedp.DefaultMaxChunkBytes,
		MaxSourceSwitches:     cwedp.DefaultMaxSourceSwitches,
	})
	importOptions := s.crpImportOptions
	importOptions.Now = s.now().UTC()
	puller, err := transport.NewPuller(transport.PullerConfig{
		Broker:           broker,
		ResumeStore:      s.resumeStore,
		Registry:         s.registry,
		IntentVerifier:   s.intentVerifier,
		CRPImportOptions: &importOptions,
		AdapterProvider: transport.AdapterProvider(func(callCtx context.Context, endpoint transport.Endpoint, intent cwedp.DistributionIntent, hello cwedp.Hello, capabilities cwedp.Capabilities, offset int64) (transport.LeaseBoundAdapter, error) {
			if endpoint.Source.Kind == cwedp.SourceOffline {
				return nil, transport.ErrNetleaseRequired
			}
			adapter, factoryErr := s.adapterFactory(callCtx, req, endpoint, intent, hello, capabilities, offset)
			if factoryErr != nil {
				return nil, factoryErr
			}
			if err := transport.ValidateLeaseBoundAdapter(adapter); err != nil {
				if adapter != nil {
					_ = adapter.Close()
				}
				return nil, err
			}
			return adapter, nil
		}),
		Production: true,
	})
	if err != nil {
		return Result{}, err
	}
	defer puller.Close()
	pkg, transfer, err := puller.PullCRP(ctx, cwedp.TransferRequest{
		Intent:       req.Intent,
		Hello:        req.Hello,
		Capabilities: req.Capabilities,
		Lease:        binding,
	})
	if err != nil {
		return Result{}, err
	}
	// PullCRP verifies the CRP before returning. Re-import to obtain the sealed
	// ImportResult required by RuntimeStore.Stage; this remains pure admission
	// and does not activate or execute the staged package.
	importOptions.Now = s.now().UTC()
	imported, err := crp.Import(pkg, importOptions)
	if err != nil {
		return Result{}, err
	}
	staged, err := s.runtime.Stage(pkg, imported)
	if err != nil {
		return Result{}, err
	}
	return Result{JobID: transfer.JobID, Source: transfer.Source, Staged: staged}, nil
}

func validateRequest(req Request, expectedEpoch uint64) error {
	if req.Password == "" || req.PolicyEpoch == 0 || req.PolicyEpoch != expectedEpoch || req.TTL <= 0 || req.TTL > netlease.MaxLeaseTTL || req.MaxBytes <= 0 || req.MaxBytes > cwedp.DefaultMaxArtifactBytes || req.MaxBytes < req.Intent.Size || !validIdentity(req.Identity.ID) || !validIdentity(req.Identity.ManagementSessionID) {
		return ErrRequest
	}
	if err := req.Intent.Validate(); err != nil {
		return err
	}
	if err := req.Hello.Validate(); err != nil {
		return err
	}
	if err := req.Capabilities.Validate(); err != nil {
		return err
	}
	if req.Hello.NodeID != req.Capabilities.NodeID || req.Hello.Protocol != cwedp.ProtocolVersion {
		return ErrRequest
	}
	return nil
}

func validIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func leaseBinding(req Request, endpoint transport.Endpoint) (cwedp.LeaseBinding, error) {
	if endpoint.Source.Kind == cwedp.SourceOffline {
		return cwedp.LeaseBinding{PluginID: req.Intent.PackageID, PluginVersion: req.Intent.Version, TargetHost: "offline-cwedp", TargetPort: 1, TargetProtocol: "file", TLSFingerprint: "offline", PolicyEpoch: req.PolicyEpoch, ConfirmationID: req.Identity.ManagementSessionID}, nil
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || parsed.Hostname() == "" || endpoint.CertificateFingerprint == "" {
		return cwedp.LeaseBinding{}, ErrRequest
	}
	port := 443
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port <= 0 || port > 65535 {
			return cwedp.LeaseBinding{}, ErrRequest
		}
	}
	return cwedp.LeaseBinding{PluginID: req.Intent.PackageID, PluginVersion: req.Intent.Version, TargetHost: parsed.Hostname(), TargetPort: port, TargetProtocol: "https", TLSFingerprint: endpoint.CertificateFingerprint, PolicyEpoch: req.PolicyEpoch, ConfirmationID: req.Identity.ManagementSessionID}, nil
}

type exactLeaseVerifier struct{ want cwedp.LeaseBinding }

func (v exactLeaseVerifier) VerifyLease(got cwedp.LeaseBinding) error {
	if got != v.want {
		return ErrRequest
	}
	return nil
}
