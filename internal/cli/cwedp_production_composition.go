package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	cwedppostgres "github.com/LaokeQwQ/CheeseWAF/internal/cwedp/postgres"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
)

var (
	ErrProductionCWEDPUnavailable = errors.New("production CWEDP composition is unavailable")
	ErrProductionCWEDPConfig      = errors.New("production CWEDP runtime configuration is invalid")
)

// ProductionCWEDPOptions names runtime-owned admission and state snapshots.
// These files are deliberately outside the tracked source config. A missing
// file, empty registry, or invalid key is a hard startup failure.
type ProductionCWEDPOptions struct {
	ResumeDSN             string
	RegistryPath          string
	TrustRootsPath        string
	SourcesPath           string
	IntentKeysPath        string
	RuntimeDir            string
	MinIndependentSources int
}

type ProductionCWEDPAdmission struct {
	Registry       transport.Registry
	IntentVerifier cwedp.IntentSignatureVerifier
	ImportOptions  crp.ImportOptions
}

type productionCWEDPIntentVerifier struct {
	keys map[string]ed25519.PublicKey
}

func (v productionCWEDPIntentVerifier) Verify(intent cwedp.DistributionIntent) error {
	parts := strings.SplitN(intent.Signature, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return cwedp.ErrIntentSignature
	}
	key, ok := v.keys[parts[0]]
	if !ok {
		return cwedp.ErrIntentSignature
	}
	signature, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return cwedp.ErrIntentSignature
	}
	payload, err := cwedp.SigningBytes(intent)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return cwedp.ErrIntentSignature
	}
	return nil
}

type productionCWEDPConfigFile struct {
	Endpoints []productionCWEDPEndpoint `json:"endpoints"`
}

type productionCWEDPEndpoint struct {
	Source                 cwedp.Source `json:"source"`
	URL                    string       `json:"url"`
	Root                   string       `json:"root"`
	IndependenceGroup      string       `json:"independence_group"`
	NodeID                 string       `json:"node_id"`
	CertificateFingerprint string       `json:"certificate_fingerprint"`
	CAFile                 string       `json:"ca_file"`
	CertFile               string       `json:"cert_file"`
	KeyFile                string       `json:"key_file"`
}

type productionCWEDPIntentKeysFile struct {
	Keys []productionCWEDPIntentKey `json:"keys"`
}

type productionCWEDPIntentKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

func productionCWEDPOptions(opts ProductionStartupOptions) ProductionCWEDPOptions {
	result := opts.CWEDP
	if result.ResumeDSN == "" {
		result.ResumeDSN = opts.ControlPostgreSQL.DSN
	}
	if result.RegistryPath == "" {
		result.RegistryPath = filepath.Join(opts.DataDir, "cwedp", "registry.json")
	}
	if result.TrustRootsPath == "" {
		result.TrustRootsPath = filepath.Join(opts.DataDir, "cwedp", "trust-roots.json")
	}
	if result.SourcesPath == "" {
		result.SourcesPath = filepath.Join(opts.DataDir, "cwedp", "sources.json")
	}
	if result.IntentKeysPath == "" {
		result.IntentKeysPath = filepath.Join(opts.DataDir, "cwedp", "intent-keys.json")
	}
	if result.RuntimeDir == "" {
		result.RuntimeDir = filepath.Join(opts.DataDir, "crp-runtime")
	}
	if result.MinIndependentSources == 0 {
		result.MinIndependentSources = 1
	}
	return result
}

func openProductionCWEDPAdmission(_ context.Context, opts ProductionCWEDPOptions) (ProductionCWEDPAdmission, error) {
	if err := validateProductionCWEDPOptions(opts); err != nil {
		return ProductionCWEDPAdmission{}, err
	}
	var document productionCWEDPConfigFile
	if err := readStrictJSON(opts.RegistryPath, &document); err != nil {
		return ProductionCWEDPAdmission{}, fmt.Errorf("%w: read CWEDP registry: %v", ErrProductionCWEDPConfig, err)
	}
	endpoints := make([]transport.Endpoint, 0, len(document.Endpoints))
	for _, entry := range document.Endpoints {
		endpoint, err := openProductionCWEDPEndpoint(entry)
		if err != nil {
			return ProductionCWEDPAdmission{}, err
		}
		endpoints = append(endpoints, endpoint)
	}
	registry, err := transport.NewRegistry(endpoints)
	if err != nil {
		return ProductionCWEDPAdmission{}, fmt.Errorf("build CWEDP registry: %w", err)
	}
	sources, err := loadSourceRegistrations(opts.SourcesPath)
	if err != nil {
		return ProductionCWEDPAdmission{}, fmt.Errorf("%w: read CRP source roots: %v", ErrProductionCWEDPConfig, err)
	}
	if len(sources) == 0 {
		return ProductionCWEDPAdmission{}, fmt.Errorf("%w: CRP source roots are required", ErrProductionCWEDPConfig)
	}
	sourceRegistry, err := crp.NewSourceRegistry(sources)
	if err != nil {
		return ProductionCWEDPAdmission{}, fmt.Errorf("build CRP source registry: %w", err)
	}
	for _, endpoint := range registry.Endpoints() {
		if _, ok := sourceRegistry.SourceRoot(endpoint.Root); !ok {
			return ProductionCWEDPAdmission{}, fmt.Errorf("%w: endpoint root %q is not registered", ErrProductionCWEDPConfig, endpoint.Root)
		}
	}
	roots, err := loadTrustRoots(opts.TrustRootsPath)
	if err != nil {
		return ProductionCWEDPAdmission{}, fmt.Errorf("%w: read CRP trust roots: %v", ErrProductionCWEDPConfig, err)
	}
	trust, err := crp.NewTrustStore(roots)
	if err != nil {
		return ProductionCWEDPAdmission{}, fmt.Errorf("build CRP trust store: %w", err)
	}
	verifier, err := openProductionCWEDPIntentVerifier(opts.IntentKeysPath)
	if err != nil {
		return ProductionCWEDPAdmission{}, err
	}
	return ProductionCWEDPAdmission{
		Registry:       registry,
		IntentVerifier: verifier,
		ImportOptions: crp.ImportOptions{
			MaxManifestBytes:  crpStageMaxJSONBytes,
			MaxArtifactBytes:  crpStageMaxArchiveBytes,
			SourceRegistry:    sourceRegistry,
			TrustStore:        trust,
			AllowConfirmation: false,
			Now:               time.Now().UTC(),
		},
	}, nil
}

func openProductionCWEDPResumeStore(ctx context.Context, opts ProductionCWEDPOptions) (*cwedppostgres.ResumeStore, error) {
	if strings.TrimSpace(opts.ResumeDSN) == "" {
		return nil, fmt.Errorf("%w: PostgreSQL resume DSN is required", ErrProductionCWEDPConfig)
	}
	store, err := cwedppostgres.Open(ctx, opts.ResumeDSN)
	if err != nil {
		return nil, fmt.Errorf("open CWEDP PostgreSQL resume store: %w", err)
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("migrate CWEDP PostgreSQL resume store: %w", err)
	}
	return store, nil
}

func openProductionCWEDPRuntime(_ context.Context, opts ProductionCWEDPOptions, admission ProductionCWEDPAdmission) (*crp.RuntimeStore, error) {
	if opts.RuntimeDir == "" || !filepath.IsAbs(opts.RuntimeDir) {
		return nil, fmt.Errorf("%w: absolute CRP runtime directory is required", ErrProductionCWEDPConfig)
	}
	return crp.NewRuntimeStore(opts.RuntimeDir, crp.RuntimeStoreOptions{
		Clock: time.Now,
		HealthCheck: crp.HealthCheckFunc(func(record crp.RuntimeRecord) error {
			return validateCRPRuntimeRecord(opts.RuntimeDir, record)
		}),
		Revalidate: crp.RuntimeRevalidateFunc(func(record crp.RuntimeRecord) error {
			return revalidateCRPRuntimeRecord(opts.RuntimeDir, admission.ImportOptions.TrustStore, admission.ImportOptions.SourceRegistry, time.Now().UTC(), false, record)
		}),
	})
}

func openProductionCWEDPEndpoint(entry productionCWEDPEndpoint) (transport.Endpoint, error) {
	if entry.Source.Kind == cwedp.SourceOffline {
		if entry.CAFile != "" || entry.CertFile != "" || entry.KeyFile != "" || entry.NodeID != "" || entry.CertificateFingerprint != "" {
			return transport.Endpoint{}, fmt.Errorf("%w: offline endpoint cannot carry online TLS identity", ErrProductionCWEDPConfig)
		}
		return transport.Endpoint{Source: entry.Source, URL: entry.URL, Root: entry.Root, IndependenceGroup: entry.IndependenceGroup}, nil
	}
	if entry.CAFile == "" || entry.CertFile == "" || entry.KeyFile == "" || entry.NodeID == "" || entry.CertificateFingerprint == "" {
		return transport.Endpoint{}, fmt.Errorf("%w: online endpoint requires CA, client certificate, key, node ID, and certificate fingerprint", ErrProductionCWEDPConfig)
	}
	caPEM, err := readRegularBounded(entry.CAFile, 1<<20)
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("read CWEDP CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return transport.Endpoint{}, fmt.Errorf("%w: CWEDP CA has no certificates", ErrProductionCWEDPConfig)
	}
	certPEM, err := readRegularBounded(entry.CertFile, 1<<20)
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("read CWEDP client certificate: %w", err)
	}
	keyPEM, err := readRegularBounded(entry.KeyFile, 1<<20)
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("read CWEDP client key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("load CWEDP client certificate: %w", err)
	}
	return transport.Endpoint{
		Source: entry.Source, URL: entry.URL, Root: entry.Root, IndependenceGroup: entry.IndependenceGroup,
		NodeID: entry.NodeID, CertificateFingerprint: entry.CertificateFingerprint,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: entry.NodeID},
	}, nil
}

func openProductionCWEDPIntentVerifier(path string) (cwedp.IntentSignatureVerifier, error) {
	var document productionCWEDPIntentKeysFile
	if err := readStrictJSON(path, &document); err != nil {
		return nil, fmt.Errorf("read CWEDP intent keys: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, item := range document.Keys {
		if item.ID == "" || item.ID != strings.TrimSpace(item.ID) || item.PublicKey == "" {
			return nil, fmt.Errorf("%w: intent key ID and public key are required", ErrProductionCWEDPConfig)
		}
		raw, err := base64.StdEncoding.DecodeString(item.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid intent public key %q", ErrProductionCWEDPConfig, item.ID)
		}
		if _, exists := keys[item.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate intent key %q", ErrProductionCWEDPConfig, item.ID)
		}
		keys[item.ID] = append(ed25519.PublicKey(nil), raw...)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: at least one intent public key is required", ErrProductionCWEDPConfig)
	}
	return productionCWEDPIntentVerifier{keys: keys}, nil
}

func readStrictJSON(path string, dst any) error {
	data, err := readRegularBounded(path, 1<<20)
	if err != nil {
		return err
	}
	return decodeStrict(data, dst)
}

func readRegularBounded(path string, max int64) ([]byte, error) {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) || max <= 0 {
		return nil, fmt.Errorf("%w: absolute regular file path is required", ErrProductionCWEDPConfig)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("%w: file is not a bounded regular file", ErrProductionCWEDPConfig)
	}
	return os.ReadFile(path)
}

func validateProductionCWEDPOptions(opts ProductionCWEDPOptions) error {
	if strings.TrimSpace(opts.ResumeDSN) == "" || opts.MinIndependentSources < 1 || opts.MinIndependentSources > 2 {
		return fmt.Errorf("%w: resume DSN and source minimum are required", ErrProductionCWEDPConfig)
	}
	for _, path := range []string{opts.RegistryPath, opts.TrustRootsPath, opts.SourcesPath, opts.IntentKeysPath, opts.RuntimeDir} {
		if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) {
			return fmt.Errorf("%w: all runtime paths must be absolute and canonical", ErrProductionCWEDPConfig)
		}
	}
	return nil
}

type productionCWEDPExecutor struct {
	executor consumer.Executor
	resume   *cwedppostgres.ResumeStore
	runtime  *crp.RuntimeStore
	policy   activation.Policy
	ctx      context.Context
	cancel   context.CancelFunc

	mu       sync.Mutex
	inflight sync.WaitGroup
	closed   bool

	once sync.Once
	err  error
}

func (e *productionCWEDPExecutor) DownloadCWEDP(ctx context.Context, request consumer.Request) (consumer.Result, error) {
	if e == nil || isNilProductionDependency(e.executor) || !e.beginDownload() {
		return consumer.Result{}, ErrProductionCWEDPUnavailable
	}
	defer e.inflight.Done()

	downloadCtx, cancel := e.downloadContext(ctx)
	defer cancel()
	return e.executor.DownloadCWEDP(downloadCtx, request)
}

func (e *productionCWEDPExecutor) beginDownload() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	e.inflight.Add(1)
	return true
}

func (e *productionCWEDPExecutor) downloadContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	child, cancel := context.WithCancel(ctx)
	if e.ctx == nil {
		return child, cancel
	}
	stop := context.AfterFunc(e.ctx, cancel)
	return child, func() {
		stop()
		cancel()
	}
}

// CRPRuntime exposes the exact runtime instance owned by the CWEDP staging
// composition. Production activation must share this instance instead of
// opening a second view of the same runtime directory with a different
// authorizer or trust snapshot.
func (e *productionCWEDPExecutor) CRPRuntime() *crp.RuntimeStore {
	if e == nil {
		return nil
	}
	return e.runtime
}

// CRPActivationPolicy returns the fresh trust, revocation and on-disk
// integrity verifier created from the same immutable admission snapshot that
// opened the shared runtime. The activation service therefore cannot verify
// against a different registry or trust-root view than CWEDP staging.
func (e *productionCWEDPExecutor) CRPActivationPolicy() activation.Policy {
	if e == nil {
		return activation.Policy{}
	}
	return e.policy
}

func (e *productionCWEDPExecutor) Close() error {
	if e == nil {
		return nil
	}
	e.once.Do(func() {
		e.mu.Lock()
		e.closed = true
		if e.cancel != nil {
			e.cancel()
		}
		e.mu.Unlock()
		e.inflight.Wait()
		if e.resume != nil {
			e.err = e.resume.Close()
		}
	})
	return e.err
}

func openProductionCWEDPDownload(ctx context.Context, wiring ProductionServeWiring, admissionOpener func(context.Context, ProductionCWEDPOptions) (ProductionCWEDPAdmission, error), resumeOpener func(context.Context, ProductionCWEDPOptions) (*cwedppostgres.ResumeStore, error), runtimeOpener func(context.Context, ProductionCWEDPOptions, ProductionCWEDPAdmission) (*crp.RuntimeStore, error)) (consumer.Executor, error) {
	if wiring.TemporaryNetwork == nil || admissionOpener == nil || resumeOpener == nil || runtimeOpener == nil {
		return nil, ErrProductionCWEDPUnavailable
	}
	admission, err := admissionOpener(ctx, wiring.CWEDP)
	if err != nil {
		return nil, err
	}
	resume, err := resumeOpener(ctx, wiring.CWEDP)
	if err != nil {
		return nil, err
	}
	runtime, err := runtimeOpener(ctx, wiring.CWEDP, admission)
	if err != nil {
		_ = resume.Close()
		return nil, err
	}
	executor, err := NewProductionCWEDPConsumer(wiring.TemporaryNetwork, ProductionCWEDPConsumerOptions{
		ResumeStore: resume, Registry: admission.Registry, IntentVerifier: admission.IntentVerifier,
		CRPImportOptions: admission.ImportOptions, Runtime: runtime,
		PolicyEpoch: wiring.PolicyEpoch, MinIndependentSources: wiring.CWEDP.MinIndependentSources,
	})
	if err != nil {
		_ = resume.Close()
		return nil, err
	}
	policy := activation.Policy{VerifyRecord: func(ctx context.Context, record crp.RuntimeRecord) error {
		if ctx == nil {
			return context.Canceled
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateCRPRuntimeRecord(wiring.CWEDP.RuntimeDir, record); err != nil {
			return err
		}
		return revalidateCRPRuntimeRecord(wiring.CWEDP.RuntimeDir, admission.ImportOptions.TrustStore, admission.ImportOptions.SourceRegistry, time.Now().UTC(), false, record)
	}}
	executorParent := ctx
	if executorParent == nil {
		executorParent = context.Background()
	}
	executorCtx, cancel := context.WithCancel(executorParent)
	return &productionCWEDPExecutor{executor: executor, resume: resume, runtime: runtime, policy: policy, ctx: executorCtx, cancel: cancel}, nil
}
