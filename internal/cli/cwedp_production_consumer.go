package cli

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	cwedppostgres "github.com/LaokeQwQ/CheeseWAF/internal/cwedp/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

// ProductionCWEDPConsumerOptions deliberately contains runtime-owned trust
// objects rather than YAML fields. A deployment launcher must supply a signed
// intent verifier, immutable endpoint registry, CRP trust/admission context,
// PostgreSQL resume store and staging runtime as one reviewed composition.
type ProductionCWEDPConsumerOptions struct {
	ResumeStore           *cwedppostgres.ResumeStore
	Registry              transport.Registry
	IntentVerifier        cwedp.IntentSignatureVerifier
	CRPImportOptions      crp.ImportOptions
	Runtime               *crp.RuntimeStore
	PolicyEpoch           uint64
	MinIndependentSources int
}

// NewProductionCWEDPConsumer joins the request-scoped temporary-network
// provider to the generic CWEDP consumer. Each external Puller attempt calls
// CWEDPAdapter anew; no provider-owned lease, session, socket, or HTTP client
// is retained by the consumer.
func NewProductionCWEDPConsumer(provider ProductionTemporaryNetworkProvider, opts ProductionCWEDPConsumerOptions) (consumer.Executor, error) {
	if isNilProductionDependency(provider) || opts.ResumeStore == nil || opts.PolicyEpoch == 0 {
		return nil, ErrProductionTemporaryNetworkUnavailable
	}
	return consumer.New(consumer.Options{
		ResumeStore:           opts.ResumeStore,
		Registry:              opts.Registry,
		IntentVerifier:        opts.IntentVerifier,
		CRPImportOptions:      opts.CRPImportOptions,
		Runtime:               opts.Runtime,
		PolicyEpoch:           opts.PolicyEpoch,
		MinIndependentSources: opts.MinIndependentSources,
		AdapterFactory: func(ctx context.Context, request consumer.Request, endpoint transport.Endpoint, intent cwedp.DistributionIntent, _ cwedp.Hello, _ cwedp.Capabilities, _ int64) (transport.LeaseBoundAdapter, error) {
			target, err := productionCWEDPTarget(endpoint)
			if err != nil {
				return nil, err
			}
			if request.PolicyEpoch != opts.PolicyEpoch {
				return nil, ErrProductionTemporaryNetworkUnavailable
			}
			adapter, err := provider.CWEDPAdapter(ctx, ProductionCWEDPLeaseRequest{
				Identity:       request.Identity,
				Password:       request.Password,
				PluginID:       intent.PackageID,
				PluginVersion:  intent.Version,
				Target:         target,
				TLSFingerprint: endpoint.CertificateFingerprint,
				PolicyEpoch:    request.PolicyEpoch,
				TTL:            request.TTL,
				MaxBytes:       request.MaxBytes,
			})
			if err != nil {
				return nil, err
			}
			if err := transport.ValidateLeaseBoundAdapter(adapter); err != nil {
				if adapter != nil {
					_ = adapter.Close()
				}
				return nil, fmt.Errorf("%w: %v", ErrProductionTemporaryNetworkAdapter, err)
			}
			return adapter, nil
		},
	})
}

func productionCWEDPTarget(endpoint transport.Endpoint) (netlease.Target, error) {
	if endpoint.Source.Kind == cwedp.SourceOffline {
		return netlease.Target{}, transport.ErrNetleaseRequired
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || parsed.Hostname() == "" || endpoint.CertificateFingerprint == "" {
		return netlease.Target{}, transport.ErrNetleaseBinding
	}
	port := 443
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil {
			return netlease.Target{}, transport.ErrNetleaseBinding
		}
	}
	target := netlease.Target{Host: parsed.Hostname(), Port: port, Protocol: "https"}
	if err := target.Validate(); err != nil {
		return netlease.Target{}, err
	}
	if err := netlease.ValidateTLSFingerprint(endpoint.CertificateFingerprint); err != nil {
		return netlease.Target{}, err
	}
	return target, nil
}
