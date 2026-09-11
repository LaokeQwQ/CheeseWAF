package transport

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

func TestNewHTTPAdapterPreservesLeaseBinding(t *testing.T) {
	scope := netlease.RequestScope{
		PluginID:       "plugin",
		PluginVersion:  "1.0.0",
		Target:         netlease.Target{Host: "peer.example", Port: 443, Protocol: "https"},
		TLSFingerprint: "sha256:" + strings.Repeat("a", 64),
		PolicyEpoch:    1,
		OperatorID:     "admin",
	}
	adapter := NewHTTPAdapter(nil, "lease-1", scope)
	got, ok := adapter.(HTTPAdapter)
	if !ok {
		t.Fatalf("NewHTTPAdapter returned %T, want HTTPAdapter", adapter)
	}
	if got.Broker != nil || got.LeaseID != "lease-1" || got.Scope != scope {
		t.Fatalf("adapter binding=%+v, want lease and scope preserved", got)
	}
}

func TestFilePullUsesAuthorizedSourceAndResumes(t *testing.T) {
	data := []byte("0123456789abcdef")
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.crp")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "file://" + path, Root: "root-offline", IndependenceGroup: "offline"}, Endpoint{Source: cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}, URL: "https://peer.example/artifact", Root: "root-peer", IndependenceGroup: "peer", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64)})
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MaxSourceSwitches: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{source, {Kind: cwedp.SourcePeer, ID: "peer"}})
	req := cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node-a", Protocol: cwedp.ProtocolVersion, Offline: true}, Capabilities: cwedp.Capabilities{NodeID: "node-a", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4}, Lease: validLease()}
	result, err := puller.Pull(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || !bytes.Equal(result.Artifact, data) || result.Source.ID != source.ID {
		t.Fatalf("result=%+v", result)
	}
}

func TestPullRejectsUnauthorizedEndpointAndOfflineNetwork(t *testing.T) {
	data := []byte("abc")
	registry := mustRegistry(t, Endpoint{Source: cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}, URL: "https://peer.example/artifact", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64), Root: "root-peer", IndependenceGroup: "peer"})
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	unauthorized := intentForBytes(data, []cwedp.Source{{Kind: cwedp.SourcePeer, ID: "missing"}})
	req := cwedp.TransferRequest{Intent: unauthorized, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 4}, Lease: validLease()}
	if _, err := puller.Pull(context.Background(), req); !errors.Is(err, ErrUnauthorizedSource) {
		t.Fatalf("unauthorized err=%v", err)
	}

	offline := intentForBytes(data, []cwedp.Source{{Kind: cwedp.SourcePeer, ID: "peer"}})
	req.Intent = offline
	req.Hello.Offline = true
	if _, err := puller.Pull(context.Background(), req); !errors.Is(err, cwedp.ErrOfflineSource) {
		t.Fatalf("offline err=%v", err)
	}
}

func TestRegistryRejectsHTTPForOfflineCRPSource(t *testing.T) {
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	_, err := NewRegistry([]Endpoint{{
		Source:            source,
		URL:               "http://127.0.0.1:1/offline.crp",
		Root:              "root-offline",
		IndependenceGroup: "offline",
	}})
	if !errors.Is(err, cwedp.ErrOfflineSource) {
		t.Fatalf("HTTP offline endpoint accepted: %v", err)
	}
}

func TestRegistryRejectsCustomAdapterForOfflineCRPSource(t *testing.T) {
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	_, err := NewRegistry([]Endpoint{{
		Source:            source,
		URL:               "file:///tmp/offline.crp",
		Root:              "root-offline",
		IndependenceGroup: "offline",
		Adapter: AdapterFunc(func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (io.ReadCloser, error) {
			return nil, errors.New("network")
		}),
	}})
	if !errors.Is(err, cwedp.ErrOfflineSource) {
		t.Fatalf("custom offline adapter accepted: %v", err)
	}
}

func TestRegistryRejectsNonHTTPSForOnlineSources(t *testing.T) {
	for _, kind := range []cwedp.SourceKind{cwedp.SourceOTA, cwedp.SourceSeed, cwedp.SourcePeer} {
		for _, rawURL := range []string{"file:///tmp/package.crp", "http://updates.example/package.crp"} {
			_, err := NewRegistry([]Endpoint{{
				Source:            cwedp.Source{Kind: kind, ID: "online"},
				URL:               rawURL,
				Root:              "root-online",
				IndependenceGroup: "online",
			}})
			if !errors.Is(err, ErrRegistryConfig) {
				t.Fatalf("kind=%s URL=%q accepted: %v", kind, rawURL, err)
			}
		}
	}
}

func TestRegistryRejectsUnboundAdapterForOnlineSource(t *testing.T) {
	_, err := NewRegistry([]Endpoint{{
		Source:                 cwedp.Source{Kind: cwedp.SourceOTA, ID: "ota"},
		URL:                    "https://updates.example/package.crp",
		Root:                   "root-ota",
		IndependenceGroup:      "ota",
		CertificateFingerprint: "sha256:" + strings.Repeat("a", 64),
		Adapter: AdapterFunc(func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("bypass")), nil
		}),
	}})
	if !errors.Is(err, ErrRegistryConfig) {
		t.Fatalf("online source accepted a public unbound adapter: %v", err)
	}
}

func TestRegistryRejectsForgedHTTPAdapterCapability(t *testing.T) {
	_, err := NewRegistry([]Endpoint{{
		Source:                 cwedp.Source{Kind: cwedp.SourceOTA, ID: "ota"},
		URL:                    "https://updates.example/package.crp",
		Root:                   "root-ota",
		IndependenceGroup:      "ota",
		CertificateFingerprint: "sha256:" + strings.Repeat("a", 64),
		Adapter: HTTPAdapter{
			Broker:  &netlease.Broker{},
			LeaseID: "forged-lease",
			Scope:   netlease.RequestScope{PluginID: "plugin", PluginVersion: "1", Target: netlease.Target{Host: "updates.example", Port: 443, Protocol: "https"}, TLSFingerprint: "sha256:" + strings.Repeat("a", 64), PolicyEpoch: 1, OperatorID: "admin", TemporaryEgress: true},
		},
	}})
	if !errors.Is(err, ErrRegistryConfig) {
		t.Fatalf("forged HTTPAdapter capability was accepted: %v", err)
	}
}

func TestHTTPAdapterOfflineSourceNeverContactsNetwork(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer srv.Close()
	data := []byte("abc")
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	_, err := (HTTPAdapter{}).Open(context.Background(), Endpoint{Source: source, URL: srv.URL}, intentForBytes(data, []cwedp.Source{source}), cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion, Offline: true}, cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4}, 0)
	if !errors.Is(err, cwedp.ErrOfflineSource) {
		t.Fatalf("HTTP adapter accepted offline network source: %v", err)
	}
	if called {
		t.Fatal("offline source contacted an HTTP server")
	}
}

func TestHTTPAdapterRequiresNetLeaseForOnlineSource(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte("unexpected"))
	}))
	defer srv.Close()

	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}
	_, err := (HTTPAdapter{}).Open(context.Background(), Endpoint{Source: source, URL: srv.URL}, intentForBytes([]byte("unexpected"), []cwedp.Source{source}), cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 32}, 0)
	if !errors.Is(err, ErrNetleaseRequired) {
		t.Fatalf("online source without netlease returned %v, want %v", err, ErrNetleaseRequired)
	}
	if called {
		t.Fatal("online source without netlease contacted the network")
	}
}

func TestPullerFailsClosedWhenOnlineSourceHasNoBoundAdapter(t *testing.T) {
	data := []byte("abc")
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}
	registry := mustRegistry(t,
		Endpoint{Source: source, URL: "https://peer.example/artifact", Root: "root-peer", IndependenceGroup: "peer", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64)},
		Endpoint{Source: cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}, URL: "file:///tmp/unused", Root: "root-offline", IndependenceGroup: "offline"},
	)
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MaxSourceSwitches: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{source, {Kind: cwedp.SourceOffline, ID: "offline"}})
	_, err = puller.Pull(context.Background(), cwedp.TransferRequest{
		Intent:       intent,
		Hello:        cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion},
		Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer, cwedp.SourceOffline}, MaxChunkSize: 4},
		Lease:        validLease(),
	})
	if !errors.Is(err, ErrNetleaseRequired) {
		t.Fatalf("missing online adapter returned %v, want %v", err, ErrNetleaseRequired)
	}
	state, loadErr := store.Load(context.Background(), intent.ID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(state.QuarantinedSources) != 0 || state.Source.ID != source.ID {
		t.Fatalf("configuration failure was hidden by quarantine: %+v", state)
	}
}

func TestRegistryRequiresCanonicalPinForOnlineHTTPS(t *testing.T) {
	for _, pin := range []string{"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63)} {
		_, err := NewRegistry([]Endpoint{{
			Source: cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}, URL: "https://peer.example/artifact", Root: "root-peer", IndependenceGroup: "peer", CertificateFingerprint: pin,
		}})
		if !errors.Is(err, ErrRegistryConfig) {
			t.Fatalf("pin %q accepted: %v", pin, err)
		}
	}
}

func TestPullerRejectsUnboundAdapterProviderBeforeOpen(t *testing.T) {
	data := []byte("provider-data")
	source := cwedp.Source{Kind: cwedp.SourceOTA, ID: "ota"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "https://ota.example/artifact", Root: "root-ota", IndependenceGroup: "ota", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64)})
	store := cwedp.NewMemoryResumeStore()
	protocolBroker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	providerCalls := 0
	opened := false
	puller, err := NewPuller(PullerConfig{
		Broker:      protocolBroker,
		ResumeStore: store,
		Registry:    registry,
		ChunkSize:   4,
		AdapterProvider: func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (Adapter, error) {
			providerCalls++
			return AdapterFunc(func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (io.ReadCloser, error) {
				opened = true
				return io.NopCloser(bytes.NewReader(data)), nil
			}), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{source})
	_, err = puller.Pull(context.Background(), cwedp.TransferRequest{
		Intent:       intent,
		Hello:        cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion},
		Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOTA}, MaxChunkSize: 4},
		Lease:        validLease(),
	})
	if !errors.Is(err, ErrNetleaseRequired) {
		t.Fatalf("unbound provider returned %v, want %v", err, ErrNetleaseRequired)
	}
	if providerCalls != 1 || opened {
		t.Fatalf("providerCalls=%d opened=%v, want one provider call and no adapter I/O", providerCalls, opened)
	}
	state, loadErr := store.Load(context.Background(), intent.ID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.Source != source || len(state.QuarantinedSources) != 0 {
		t.Fatalf("unbound provider changed source health state: %+v", state)
	}
}

func TestPullerUsesLeaseBoundAdapterProvider(t *testing.T) {
	data := []byte("lease-bound-provider")
	var sourceNodeID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		peerHello, _ := EncodeHelloHeader(cwedp.Hello{NodeID: sourceNodeID, Protocol: cwedp.ProtocolVersion})
		peerCaps, _ := EncodeCapabilitiesHeader(cwedp.Capabilities{NodeID: sourceNodeID, ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOTA}, MaxChunkSize: 64})
		w.Header().Set(HeaderPeerHello, peerHello)
		w.Header().Set(HeaderPeerCaps, peerCaps)
		_, _ = w.Write(data)
	}))
	defer server.Close()
	sourceNodeID, tlsConfig := onlineTLSIdentityForServer(t, server)
	fingerprint := CertificateFingerprint(server.Certificate())
	netBroker, lease, scope := issueHTTPTestLease(t, server, fingerprint)
	source := cwedp.Source{Kind: cwedp.SourceOTA, ID: "ota"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: server.URL, Root: "root-ota", IndependenceGroup: "ota", NodeID: sourceNodeID, CertificateFingerprint: fingerprint, TLSConfig: tlsConfig})
	store := cwedp.NewMemoryResumeStore()
	protocolBroker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	providerCalls := 0
	puller, err := NewPuller(PullerConfig{
		Broker:      protocolBroker,
		ResumeStore: store,
		Registry:    registry,
		AdapterProvider: func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (Adapter, error) {
			providerCalls++
			return NewHTTPAdapter(netBroker, lease.ID, scope), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	result, err := puller.Pull(context.Background(), cwedp.TransferRequest{
		Intent:       intentForBytes(data, []cwedp.Source{source}),
		Hello:        cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion},
		Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOTA}, MaxChunkSize: 64},
		Lease:        validLease(),
	})
	if err != nil || !result.Complete || !bytes.Equal(result.Artifact, data) || providerCalls != 1 {
		t.Fatalf("result=%+v providerCalls=%d err=%v", result, providerCalls, err)
	}
}

func TestPullerRejectsNilAdapterFromOnlineProvider(t *testing.T) {
	source := cwedp.Source{Kind: cwedp.SourceOTA, ID: "ota"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "https://ota.example/artifact", Root: "root-ota", IndependenceGroup: "ota", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64)})
	store := cwedp.NewMemoryResumeStore()
	protocolBroker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	puller, err := NewPuller(PullerConfig{
		Broker:      protocolBroker,
		ResumeStore: store,
		Registry:    registry,
		AdapterProvider: func(context.Context, Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (Adapter, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	_, err = puller.Pull(context.Background(), cwedp.TransferRequest{
		Intent:       intentForBytes([]byte("data"), []cwedp.Source{source}),
		Hello:        cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion},
		Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOTA}, MaxChunkSize: 4},
		Lease:        validLease(),
	})
	if !errors.Is(err, ErrNetleaseRequired) {
		t.Fatalf("nil online adapter returned %v, want %v", err, ErrNetleaseRequired)
	}
}

func TestPullerDoesNotQuarantineNetLeasePreDialRejection(t *testing.T) {
	data := []byte("not-transferred")
	online := cwedp.Source{Kind: cwedp.SourceOTA, ID: "ota"}
	offline := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	target := netlease.Target{Host: "updates.example", Port: 443, Protocol: "https"}
	network := &countingFailureNetwork{}
	netBroker, lease, scope := issueHTTPTestLeaseForTarget(t, target, fingerprint, network)
	scope.PluginVersion = "scope-substitution"
	tlsConfig := onlineTestTLSConfig(t)
	registry := mustRegistry(t,
		Endpoint{Source: online, URL: "https://updates.example/package.crp", Root: "root-ota", IndependenceGroup: "ota", NodeID: "updates.example", CertificateFingerprint: fingerprint, TLSConfig: tlsConfig, Adapter: NewHTTPAdapter(netBroker, lease.ID, scope)},
		Endpoint{Source: offline, URL: "file:///tmp/must-not-be-opened", Root: "root-offline", IndependenceGroup: "offline"},
	)
	store := cwedp.NewMemoryResumeStore()
	protocolBroker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MaxSourceSwitches: 1})
	puller, err := NewPuller(PullerConfig{Broker: protocolBroker, ResumeStore: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{online, offline})
	_, err = puller.Pull(context.Background(), cwedp.TransferRequest{
		Intent:       intent,
		Hello:        cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion},
		Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOTA, cwedp.SourceOffline}, MaxChunkSize: 4},
		Lease:        validLease(),
	})
	if !errors.Is(err, netlease.ErrLeaseScope) || !errors.Is(err, netlease.ErrBeforeDial) {
		t.Fatalf("pre-dial rejection returned %v", err)
	}
	if network.resolveCount != 0 || network.dialCount != 0 {
		t.Fatalf("pre-dial rejection performed I/O: resolves=%d dials=%d", network.resolveCount, network.dialCount)
	}
	state, loadErr := store.Load(context.Background(), intent.ID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.Source != online || len(state.QuarantinedSources) != 0 {
		t.Fatalf("pre-dial rejection changed source health state: %+v", state)
	}
}

func TestHTTPAdapterOverridesCustomRedirectPolicy(t *testing.T) {
	targetCalls := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls++
		_, _ = w.Write([]byte("target"))
	}))
	defer target.Close()
	sourceServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer sourceServer.Close()
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}
	broker, lease, scope := issueHTTPTestLease(t, sourceServer, CertificateFingerprint(sourceServer.Certificate()))
	nodeID, tlsConfig := onlineTLSIdentityForServer(t, sourceServer)
	_, err := NewHTTPAdapter(broker, lease.ID, scope).(HTTPAdapter).Open(context.Background(), Endpoint{Source: source, URL: sourceServer.URL, NodeID: nodeID, CertificateFingerprint: CertificateFingerprint(sourceServer.Certificate()), TLSConfig: tlsConfig}, intentForBytes(bytes.Repeat([]byte("x"), 1024), []cwedp.Source{source}), cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 8}, 0)
	if !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("redirect response was accepted: %v", err)
	}
	if targetCalls != 0 {
		t.Fatalf("redirect target was contacted %d times", targetCalls)
	}
}

func TestHTTPAdapterRejectsSelfReportedPeerNodeID(t *testing.T) {
	peerHello, _ := EncodeHelloHeader(cwedp.Hello{NodeID: "attacker-node", Protocol: cwedp.ProtocolVersion})
	peerCaps, _ := EncodeCapabilitiesHeader(cwedp.Capabilities{NodeID: "attacker-node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 8})
	headers := make(http.Header)
	headers.Set(HeaderPeerHello, peerHello)
	headers.Set(HeaderPeerCaps, peerCaps)
	err := validatePeerHandshake(headers, true, "registered-node")
	if !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("self-reported peer identity accepted: %v", err)
	}
}

func TestProductionPullerRequiresExplicitOnlineTLSIdentity(t *testing.T) {
	for _, kind := range []cwedp.SourceKind{cwedp.SourceOTA, cwedp.SourceSeed, cwedp.SourcePeer} {
		t.Run(string(kind), func(t *testing.T) {
			source := cwedp.Source{Kind: kind, ID: "source"}
			registry := mustRegistry(t, Endpoint{Source: source, URL: "https://source.invalid/artifact", Root: "root-source", IndependenceGroup: "source", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64)})
			store := cwedp.NewMemoryResumeStore()
			broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
			if _, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, Production: true, IntentVerifier: IntentSignatureVerifierFunc(func(cwedp.DistributionIntent) error { return nil }), CRPImportOptions: &crp.ImportOptions{}}); !errors.Is(err, ErrPullConfig) {
				t.Fatalf("production puller accepted %s without complete TLS identity: %v", kind, err)
			}
		})
	}
}

func TestProductionPullerRejectsIncompleteMTLSMaterialForEveryOnlineKind(t *testing.T) {
	for _, kind := range []cwedp.SourceKind{cwedp.SourceOTA, cwedp.SourceSeed, cwedp.SourcePeer} {
		t.Run(string(kind), func(t *testing.T) {
			source := cwedp.Source{Kind: kind, ID: "source"}
			registry := mustRegistry(t, Endpoint{Source: source, URL: "https://source.invalid/artifact", Root: "root-source", IndependenceGroup: "source", NodeID: "source-node", CertificateFingerprint: "sha256:" + strings.Repeat("a", 64), TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}}}})
			store := cwedp.NewMemoryResumeStore()
			broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
			if _, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, Production: true, IntentVerifier: IntentSignatureVerifierFunc(func(cwedp.DistributionIntent) error { return nil }), CRPImportOptions: &crp.ImportOptions{}}); !errors.Is(err, ErrPullConfig) {
				t.Fatalf("production puller accepted incomplete %s mTLS trust material: %v", kind, err)
			}
		})
	}
}

func TestHTTPAdapterRejectsMissingOnlineMTLSIdentityBeforeNetwork(t *testing.T) {
	for _, kind := range []cwedp.SourceKind{cwedp.SourceOTA, cwedp.SourceSeed, cwedp.SourcePeer} {
		t.Run(string(kind), func(t *testing.T) {
			network := &countingFailureNetwork{}
			fingerprint := "sha256:" + strings.Repeat("a", 64)
			target := netlease.Target{Host: "source.invalid", Port: 443, Protocol: "https"}
			broker, lease, scope := issueHTTPTestLeaseForTarget(t, target, fingerprint, network)
			source := cwedp.Source{Kind: kind, ID: "source"}
			_, err := NewHTTPAdapter(broker, lease.ID, scope).Open(context.Background(), Endpoint{Source: source, URL: "https://source.invalid/artifact", CertificateFingerprint: fingerprint}, intentForBytes([]byte("x"), []cwedp.Source{source}), cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{kind}, MaxChunkSize: 1}, 0)
			if !errors.Is(err, ErrPullConfig) {
				t.Fatalf("adapter accepted incomplete %s TLS identity: %v", kind, err)
			}
			if network.resolveCount != 0 || network.dialCount != 0 {
				t.Fatal("incomplete TLS identity reached network transport")
			}
		})
	}
}

func TestHTTPAdapterUsesEndpointMTLSAndCertificateVerifier(t *testing.T) {
	for _, kind := range []cwedp.SourceKind{cwedp.SourceOTA, cwedp.SourceSeed, cwedp.SourcePeer} {
		t.Run(string(kind), func(t *testing.T) {
			clientRoots, clientCertificate := newClientCertificate(t)
			clientPresented := false
			verifierCalled := false
			var sourceNodeID string
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientPresented = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
				peerHello, _ := EncodeHelloHeader(cwedp.Hello{NodeID: sourceNodeID, Protocol: cwedp.ProtocolVersion})
				peerCaps, _ := EncodeCapabilitiesHeader(cwedp.Capabilities{NodeID: sourceNodeID, ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{kind}, MaxChunkSize: 16})
				w.Header().Set(HeaderPeerHello, peerHello)
				w.Header().Set(HeaderPeerCaps, peerCaps)
				_, _ = w.Write([]byte("mtls-data"))
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
			server.StartTLS()
			defer server.Close()
			if len(server.Certificate().DNSNames) == 0 {
				t.Fatal("httptest certificate has no DNS identity")
			}
			sourceNodeID = server.Certificate().DNSNames[0]
			serverRoots := x509.NewCertPool()
			serverRoots.AddCert(server.Certificate())
			fingerprint := CertificateFingerprint(server.Certificate())
			broker, lease, scope := issueHTTPTestLease(t, server, fingerprint)
			source := cwedp.Source{Kind: kind, ID: "source"}
			endpoint := Endpoint{
				Source:                 source,
				URL:                    server.URL,
				NodeID:                 sourceNodeID,
				CertificateFingerprint: fingerprint,
				TLSConfig:              &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverRoots, Certificates: []tls.Certificate{clientCertificate}},
				CertificateVerifier: CertificateVerifierFunc(func(gotSource cwedp.Source, cert *x509.Certificate) error {
					verifierCalled = true
					if gotSource != source || cert == nil {
						return ErrPeerIdentity
					}
					return nil
				}),
			}
			body, err := NewHTTPAdapter(broker, lease.ID, scope).Open(context.Background(), endpoint, intentForBytes([]byte("mtls-data"), []cwedp.Source{source}), cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{kind}, MaxChunkSize: 16}, 0)
			if err != nil {
				t.Fatalf("mTLS pull failed: %v", err)
			}
			defer body.Close()
			if _, err := io.ReadAll(body); err != nil {
				t.Fatal(err)
			}
			if !clientPresented || !verifierCalled {
				t.Fatalf("clientPresented=%v verifierCalled=%v", clientPresented, verifierCalled)
			}
		})
	}
}

func TestHTTPAdapterRejectsPeerCertificateNodeIDMismatchBeforeRequest(t *testing.T) {
	clientRoots, clientCertificate := newClientCertificate(t)
	requestCount := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		_, _ = w.Write([]byte("must-not-be-read"))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	server.StartTLS()
	defer server.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	fingerprint := CertificateFingerprint(server.Certificate())
	broker, lease, scope := issueHTTPTestLease(t, server, fingerprint)
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}
	_, err := NewHTTPAdapter(broker, lease.ID, scope).Open(context.Background(), Endpoint{
		Source:                 source,
		URL:                    server.URL,
		NodeID:                 "registered-peer.invalid",
		CertificateFingerprint: fingerprint,
		TLSConfig:              &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverRoots, Certificates: []tls.Certificate{clientCertificate}},
	}, intentForBytes([]byte("must-not-be-read"), []cwedp.Source{source}), cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 32}, 0)
	if !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("certificate identity mismatch returned %v, want %v", err, ErrPeerIdentity)
	}
	if requestCount != 0 {
		t.Fatalf("certificate identity mismatch sent %d HTTP requests", requestCount)
	}
}

func TestHTTPAdapterKeepsMTLSAndLeafPinFailClosed(t *testing.T) {
	clientRoots, clientCertificate := newClientCertificate(t)
	requestCount := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		_, _ = w.Write([]byte("must-not-be-read"))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	server.StartTLS()
	defer server.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	correctFingerprint := CertificateFingerprint(server.Certificate())
	wrongFingerprint := "sha256:" + strings.Repeat("b", 64)
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}

	tests := []struct {
		name        string
		fingerprint string
		config      *tls.Config
		expected    error
	}{
		{name: "missing client certificate", fingerprint: correctFingerprint, config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverRoots}},
		{name: "untrusted server CA", fingerprint: correctFingerprint, config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{clientCertificate}}},
		{name: "leaf pin mismatch", fingerprint: wrongFingerprint, config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverRoots, Certificates: []tls.Certificate{clientCertificate}}, expected: netlease.ErrTLSFingerprint},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestCount = 0
			broker, lease, scope := issueHTTPTestLease(t, server, test.fingerprint)
			_, err := NewHTTPAdapter(broker, lease.ID, scope).Open(context.Background(), Endpoint{Source: source, URL: server.URL, NodeID: server.Certificate().DNSNames[0], CertificateFingerprint: test.fingerprint, TLSConfig: test.config}, intentForBytes([]byte("must-not-be-read"), []cwedp.Source{source}), cwedp.Hello{NodeID: "client", Protocol: cwedp.ProtocolVersion}, cwedp.Capabilities{NodeID: "client", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 32}, 0)
			if err == nil || (test.expected != nil && !errors.Is(err, test.expected)) {
				t.Fatalf("err=%v, want failure matching %v", err, test.expected)
			}
			if requestCount != 0 {
				t.Fatalf("failed TLS policy sent %d HTTP requests", requestCount)
			}
		})
	}
}

func TestPullCRPRejectsUnsignedIntentBeforeTransfer(t *testing.T) {
	data := []byte("not-used")
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	path := filepath.Join(t.TempDir(), "artifact.crp")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "file://" + path, Root: "root-offline", IndependenceGroup: "offline"})
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{source})
	_, _, err = puller.PullCRP(context.Background(), cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion, Offline: true}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4}, Lease: validLease()})
	if !errors.Is(err, ErrIntentSignature) {
		t.Fatalf("unsigned DistributionIntent was accepted: %v", err)
	}
}

func TestPullRejectsIntentWhenSignatureVerifierFails(t *testing.T) {
	called := false
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "file:///tmp/offline.crp", Root: "root-offline", IndependenceGroup: "offline", Adapter: FileAdapter{}})
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, IntentVerifier: IntentSignatureVerifierFunc(func(cwedp.DistributionIntent) error {
		called = true
		return errors.New("bad signature")
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes([]byte("abc"), []cwedp.Source{source})
	_, err = puller.Pull(context.Background(), cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion, Offline: true}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4}, Lease: validLease()})
	if !errors.Is(err, ErrIntentSignature) || !called {
		t.Fatalf("failed intent signature was accepted or verifier not called: err=%v called=%v", err, called)
	}
}

func TestPullCRPRunsCRPImportAdmissionChecks(t *testing.T) {
	archive := makeUnsignedCRPArchive(t)
	path := filepath.Join(t.TempDir(), "artifact.crp")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "file://" + path, Root: "root-offline", IndependenceGroup: "offline"})
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	crpRegistry, err := crp.NewSourceRegistry([]crp.SourceRootRegistration{{ID: "root", NamespacePrefixes: []string{"official/"}, Sources: []string{"offline"}}})
	if err != nil {
		t.Fatal(err)
	}
	puller, err := NewPuller(PullerConfig{
		Broker:         broker,
		ResumeStore:    store,
		Registry:       registry,
		IntentVerifier: IntentSignatureVerifierFunc(func(cwedp.DistributionIntent) error { return nil }),
		CRPImportOptions: &crp.ImportOptions{
			MaxManifestBytes: 4096,
			MaxArtifactBytes: 4096,
			SourceRegistry:   crpRegistry,
			Now:              time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC),
			CurrentRelease:   crp.Release{Version: "2.0.0", Sequence: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(archive, []cwedp.Source{source})
	intent.Signature = "intent-signature"
	_, _, err = puller.PullCRP(context.Background(), cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion, Offline: true}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 64}, Lease: validLease()})
	if !errors.Is(err, crp.ErrDowngrade) {
		t.Fatalf("CRP release downgrade bypassed PullCRP admission: %v", err)
	}
}

func TestHTTPPullSendsHelloCapabilitiesAndUsesRange(t *testing.T) {
	data := []byte("abcdefghijk")
	var mu sync.Mutex
	var ranges []string
	var hello, capabilities string
	var sourceNodeID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		hello = r.Header.Get(HeaderHello)
		capabilities = r.Header.Get(HeaderCapabilities)
		mu.Unlock()
		peerHello, _ := EncodeHelloHeader(cwedp.Hello{NodeID: sourceNodeID, Protocol: cwedp.ProtocolVersion})
		peerCaps, _ := EncodeCapabilitiesHeader(cwedp.Capabilities{NodeID: sourceNodeID, ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 3})
		w.Header().Set(HeaderPeerHello, peerHello)
		w.Header().Set(HeaderPeerCaps, peerCaps)
		start := int64(0)
		if r.Header.Get("Range") != "" {
			_, _ = fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &start)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, int64(len(data))-1, len(data)))
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write(data[start:])
	}))
	defer srv.Close()
	sourceNodeID, tlsConfig := onlineTLSIdentityForServer(t, srv)
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}
	fingerprint := CertificateFingerprint(srv.Certificate())
	netBroker, lease, scope := issueHTTPTestLease(t, srv, fingerprint)
	registry := mustRegistry(t, Endpoint{Source: source, URL: srv.URL, Root: "root-peer", IndependenceGroup: "peer", NodeID: sourceNodeID, CertificateFingerprint: fingerprint, TLSConfig: tlsConfig, Adapter: NewHTTPAdapter(netBroker, lease.ID, scope)}, Endpoint{Source: cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}, URL: "file:///tmp/unused", Root: "root-offline", IndependenceGroup: "offline"})
	store := cwedp.NewMemoryResumeStore()
	protocolBroker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}})
	puller, err := NewPuller(PullerConfig{Broker: protocolBroker, ResumeStore: store, Registry: registry, ChunkSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{source, {Kind: cwedp.SourceOffline, ID: "offline"}})
	req := cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 3}, Lease: validLease()}
	result, err := puller.Pull(context.Background(), req)
	if err != nil || !result.Complete || !bytes.Equal(result.Artifact, data) {
		state, _ := store.Load(context.Background(), req.Intent.ID)
		t.Fatalf("result=%+v err=%v state=%+v", result, err, state)
	}
	if hello == "" || capabilities == "" || len(ranges) < 1 {
		t.Fatalf("headers/ranges missing hello=%q caps=%q ranges=%v", hello, capabilities, ranges)
	}
}

func TestHTTPPullTLSFingerprintVerifier(t *testing.T) {
	data := []byte("tls-artifact")
	var sourceNodeID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerHello, _ := EncodeHelloHeader(cwedp.Hello{NodeID: sourceNodeID, Protocol: cwedp.ProtocolVersion})
		peerCaps, _ := EncodeCapabilitiesHeader(cwedp.Capabilities{NodeID: sourceNodeID, ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 4})
		w.Header().Set(HeaderPeerHello, peerHello)
		w.Header().Set(HeaderPeerCaps, peerCaps)
		_, _ = w.Write(data)
	}))
	defer srv.Close()
	sourceNodeID, tlsConfig := onlineTLSIdentityForServer(t, srv)
	fp := CertificateFingerprint(srv.Certificate())
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "peer"}
	netBroker, lease, scope := issueHTTPTestLease(t, srv, fp)
	registry := mustRegistry(t, Endpoint{Source: source, URL: srv.URL, Root: "root-peer", IndependenceGroup: "peer", NodeID: sourceNodeID, CertificateFingerprint: fp, TLSConfig: tlsConfig, Adapter: NewHTTPAdapter(netBroker, lease.ID, scope)}, Endpoint{Source: cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}, URL: "file:///tmp/unused", Root: "root-offline", IndependenceGroup: "offline"})
	store := cwedp.NewMemoryResumeStore()
	protocolBroker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}})
	puller, err := NewPuller(PullerConfig{Broker: protocolBroker, ResumeStore: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	req := cwedp.TransferRequest{Intent: intentForBytes(data, []cwedp.Source{source, {Kind: cwedp.SourceOffline, ID: "offline"}}), Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: 4}, Lease: validLease()}
	result, err := puller.Pull(context.Background(), req)
	if err != nil || !result.Complete || !bytes.Equal(result.Artifact, data) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestFingerprintVerifierRejectsMismatch(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("certificate")}
	if err := VerifyCertificateFingerprint(cert, "sha256:00"); !errors.Is(err, ErrCertificateFingerprint) {
		t.Fatalf("err=%v", err)
	}
}

func TestPullQuarantinesTransportFailureAndSwitchesSource(t *testing.T) {
	data := []byte("fallback-data")
	first := cwedp.Source{Kind: cwedp.SourcePeer, ID: "bad-peer"}
	second := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	target := netlease.Target{Host: "bad-peer.example", Port: 443, Protocol: "https"}
	netBroker, lease, scope := issueHTTPTestLeaseForTarget(t, target, fingerprint, &failingDialNetwork{})
	registry := mustRegistry(t,
		Endpoint{Source: first, URL: "https://bad-peer.example/artifact", Root: "root-bad", IndependenceGroup: "bad", CertificateFingerprint: fingerprint, Adapter: NewHTTPAdapter(netBroker, lease.ID, scope)},
		Endpoint{Source: second, URL: "file://" + path, Root: "root-good", IndependenceGroup: "good"},
	)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MaxSourceSwitches: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(data, []cwedp.Source{first, second})
	result, err := puller.Pull(context.Background(), cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer, cwedp.SourceOffline}, MaxChunkSize: 4}, Lease: validLease()})
	if err != nil || !result.Complete || result.Source.ID != second.ID || !bytes.Equal(result.Artifact, data) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	state, err := store.Load(context.Background(), intent.ID)
	if err != nil || len(state.QuarantinedSources) != 1 || state.QuarantinedSources[0].Reason != cwedp.QuarantineTransport {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestPullHandlesBrokerIntegritySwitchAndResetsOffset(t *testing.T) {
	good := []byte("integrity-good")
	bad := []byte("integrity-bad!")
	first := cwedp.Source{Kind: cwedp.SourceOffline, ID: "bad-offline"}
	second := cwedp.Source{Kind: cwedp.SourceOffline, ID: "good-offline"}
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.crp")
	goodPath := filepath.Join(dir, "good.crp")
	if err := os.WriteFile(badPath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goodPath, good, 0o600); err != nil {
		t.Fatal(err)
	}
	registry := mustRegistry(t,
		Endpoint{Source: first, URL: "file://" + badPath, Root: "root-bad", IndependenceGroup: "bad"},
		Endpoint{Source: second, URL: "file://" + goodPath, Root: "root-good", IndependenceGroup: "good"},
	)
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MaxSourceSwitches: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry, ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	intent := intentForBytes(good, []cwedp.Source{first, second})
	result, err := puller.Pull(context.Background(), cwedp.TransferRequest{Intent: intent, Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion, Offline: true}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4}, Lease: validLease()})
	if err != nil || !result.Complete || result.Source.ID != second.ID || !bytes.Equal(result.Artifact, good) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	state, err := store.Load(context.Background(), intent.ID)
	if err != nil || state.Source.ID != second.ID || state.NextOffset != int64(len(good)) || len(state.QuarantinedSources) != 1 || state.QuarantinedSources[0].Reason != cwedp.QuarantineIntegrity {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestCRPReaderUsesStrictArchiveParser(t *testing.T) {
	reader := CRPReader{}
	if _, err := reader.Read(bytes.NewReader([]byte("not-a-crp"))); !errors.Is(err, crp.ErrArchiveEntry) {
		t.Fatalf("err=%v", err)
	}
}

func TestPullCompletesEmptyAuthorizedArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.crp")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	registry := mustRegistry(t, Endpoint{Source: source, URL: "file://" + path, Root: "root", IndependenceGroup: "group"})
	store := cwedp.NewMemoryResumeStore()
	broker := cwedp.NewBroker(cwedp.BrokerConfig{Registry: registry.ProtocolRegistry(), ResumeStore: store, LeaseVerifier: allowLease{}, MinIndependentSources: 1})
	puller, err := NewPuller(PullerConfig{Broker: broker, ResumeStore: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	result, err := puller.Pull(ctx, cwedp.TransferRequest{Intent: intentForBytes(nil, []cwedp.Source{source}), Hello: cwedp.Hello{NodeID: "node", Protocol: cwedp.ProtocolVersion, Offline: true}, Capabilities: cwedp.Capabilities{NodeID: "node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4}, Lease: validLease()})
	if err != nil || !result.Complete || len(result.Artifact) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

type allowLease struct{}

func (allowLease) VerifyLease(cwedp.LeaseBinding) error { return nil }

func mustRegistry(t *testing.T, endpoints ...Endpoint) Registry {
	t.Helper()
	registry, err := NewRegistry(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func validLease() cwedp.LeaseBinding {
	return cwedp.LeaseBinding{PluginID: "plugin", PluginVersion: "1", TargetHost: "127.0.0.1", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "confirm"}
}

type transportTestAuthenticator struct{}

func (transportTestAuthenticator) VerifySession(context.Context, netlease.AdministratorIdentity, time.Time) error {
	return nil
}

func (transportTestAuthenticator) VerifyPassword(context.Context, netlease.AdministratorIdentity, string) error {
	return nil
}

type transportTestNetwork struct {
	address string
}

type failingDialNetwork struct{}

func (*failingDialNetwork) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

func (*failingDialNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("peer down")
}

type countingFailureNetwork struct {
	resolveCount int
	dialCount    int
}

func (n *countingFailureNetwork) Resolve(context.Context, string) ([]netip.Addr, error) {
	n.resolveCount++
	return []netip.Addr{netip.MustParseAddr("203.0.113.11")}, nil
}

func (n *countingFailureNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	n.dialCount++
	return nil, errors.New("unexpected dial")
}

func (t transportTestNetwork) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	return nil, fmt.Errorf("unexpected host resolution for %q", host)
}

func (t transportTestNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != t.address {
		return nil, fmt.Errorf("unexpected direct address %q, want %q", address, t.address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func issueHTTPTestLease(t *testing.T, server *httptest.Server, fingerprint string) (*netlease.Broker, netlease.Lease, netlease.RequestScope) {
	t.Helper()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	network := transportTestNetwork{address: net.JoinHostPort(host, portText)}
	return issueHTTPTestLeaseForTarget(t, netlease.Target{Host: host, Port: port, Protocol: "https"}, fingerprint, network)
}

func issueHTTPTestLeaseForTarget(t *testing.T, target netlease.Target, fingerprint string, network netlease.NetworkTransport) (*netlease.Broker, netlease.Lease, netlease.RequestScope) {
	t.Helper()
	sessions, err := netlease.NewTemporarySessionManager(netlease.TemporarySessionManagerOptions{Authenticator: transportTestAuthenticator{}})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := netlease.NewBroker(netlease.BrokerConfig{
		Enabled:              true,
		Policy:               netlease.NewOfflinePolicyWithEpoch(nil, 7),
		Sessions:             sessions,
		Transport:            network,
		Addresses:            netlease.AddressPolicyFunc(func(netlease.Target, netip.Addr) error { return nil }),
		Audit:                netlease.NewMemoryAuditSinkForTesting(),
		MaxHTTPBodyBytes:     64 << 10,
		MaxHTTPResponseBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := broker.BeginTemporarySession(context.Background(), netlease.BeginTemporarySessionRequest{Identity: netlease.AdministratorIdentity{ID: "admin"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := broker.IssueTemporary(context.Background(), netlease.ConfirmationInput{SessionID: session.ID, Password: "ignored", PluginID: "plugin", PluginVersion: "1", Target: target, TLSFingerprint: fingerprint, PolicyEpoch: 7, TTL: time.Minute, MaxBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	scope := netlease.RequestScope{PluginID: "plugin", PluginVersion: "1", Target: target, TLSFingerprint: fingerprint, PolicyEpoch: 7, OperatorID: "admin", TemporaryEgress: true}
	return broker, lease, scope
}

func onlineTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	_, clientCertificate := newClientCertificate(t)
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{clientCertificate}}
}

func onlineTLSIdentityForServer(t *testing.T, server *httptest.Server) (string, *tls.Config) {
	t.Helper()
	cert := server.Certificate()
	if cert == nil || len(cert.DNSNames) == 0 {
		t.Fatal("test TLS server certificate has no DNS identity")
	}
	config := onlineTestTLSConfig(t)
	config.RootCAs.AddCert(cert)
	return cert.DNSNames[0], config
}

func newClientCertificate(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CWEDP test client CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cwedp-client"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, tls.Certificate{Certificate: [][]byte{clientDER, caDER}, PrivateKey: clientKey, Leaf: nil}
}

func intentForBytes(data []byte, sources []cwedp.Source) cwedp.DistributionIntent {
	m := md5.Sum(data)
	a := sha1.Sum(data)
	h := sha256.Sum256(data)
	return cwedp.DistributionIntent{ID: "intent-" + hex.EncodeToString(h[:4]), PackageID: "pkg", Version: "1.0.0", Size: int64(len(data)), Digests: cwedp.Digests{MD5: hex.EncodeToString(m[:]), SHA1: hex.EncodeToString(a[:]), SHA256: hex.EncodeToString(h[:])}, Sources: sources, Signature: "signed-intent"}
}

func makeUnsignedCRPArchive(t *testing.T) []byte {
	t.Helper()
	artifact := []byte("payload")
	manifest := crp.Manifest{
		APIVersion:      crp.APIVersion,
		Kind:            crp.Kind,
		Name:            "demo",
		PluginID:        "demo",
		Version:         "1.0.0",
		Namespace:       "official/demo",
		SourceRoot:      "root",
		Source:          "offline",
		ReleaseSequence: 1,
		Artifact:        crp.Artifact{Size: int64(len(artifact)), Digests: crp.ComputeDigests(artifact)},
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	entries := map[string][]byte{
		"manifest.json":            rawManifest,
		"artifact/payload.bin":     artifact,
		"signatures/manifest.json": []byte("[]"),
	}
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
