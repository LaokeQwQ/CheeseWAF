package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/spf13/cobra"
)

type crpActivationAction string

const (
	crpActivationActionActivate crpActivationAction = "activate"
	crpActivationActionRollback crpActivationAction = "rollback"
	crpActivationMaxProbeCount                      = 64
)

// crpActivationOptions contains only explicit operator material. The command
// never invents a control-plane fence, confirmation, or sidecar endpoint.
type crpActivationOptions struct {
	runtimeDir           string
	trustRootsPath       string
	sourcesPath          string
	nowText              string
	descriptorPath       string
	pluginKey            string
	expectedRevisionText string
	clusterID            string
	nodeID               string
	controlPlaneEndpoint string
	sidecarEndpoint      string
	tlsCAFile            string
	tlsCertFile          string
	tlsKeyFile           string
	controlServerName    string
	sidecarServerName    string
	transportTimeout     time.Duration
	operationTimeout     time.Duration
	highRisk             bool
	observeProbes        int
	canaryProbes         int
	probeTimeout         time.Duration
}

func newCRPActivateCommand() *cobra.Command {
	opts := crpActivationOptions{}
	cmd := &cobra.Command{
		Use:   "activate",
		Short: "Verify a staged CRP, then request observe/canary/active promotion",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCRPActivation(cmd, crpActivationActionActivate, opts)
		},
	}
	addCRPActivationFlags(cmd, &opts)
	return cmd
}

func newCRPRollbackCommand() *cobra.Command {
	opts := crpActivationOptions{}
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Verify the exact previous CRP, then request observe/canary rollback",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCRPActivation(cmd, crpActivationActionRollback, opts)
		},
	}
	addCRPActivationFlags(cmd, &opts)
	return cmd
}

func addCRPActivationFlags(cmd *cobra.Command, opts *crpActivationOptions) {
	flags := cmd.Flags()
	flags.StringVar(&opts.runtimeDir, "runtime-dir", "", "Explicit local CRP runtime state directory")
	flags.StringVar(&opts.trustRootsPath, "trust-roots", "", "JSON file containing the explicit trust-root snapshot")
	flags.StringVar(&opts.sourcesPath, "sources", "", "JSON file containing the explicit source-registration snapshot")
	flags.StringVar(&opts.nowText, "now", "", "RFC3339 package verification time")
	flags.StringVar(&opts.descriptorPath, "descriptor", "", "JSON file containing the approved sidecar descriptor")
	flags.StringVar(&opts.pluginKey, "plugin", "", "Runtime plugin key")
	flags.StringVar(&opts.expectedRevisionText, "expected-revision", "", "Expected runtime revision for CAS")
	flags.StringVar(&opts.clusterID, "cluster-id", "", "Control-plane cluster identity")
	flags.StringVar(&opts.nodeID, "node-id", "", "WAF node identity bound to the client certificate SAN")
	flags.StringVar(&opts.controlPlaneEndpoint, "control-plane", "", "Protected HTTPS control-plane origin")
	flags.StringVar(&opts.sidecarEndpoint, "sidecar", "", "Approved HTTPS sidecar-launcher origin")
	flags.StringVar(&opts.tlsCAFile, "tls-ca", "", "PEM CA for control-plane and sidecar server verification")
	flags.StringVar(&opts.tlsCertFile, "tls-cert", "", "PEM WAF-node client certificate")
	flags.StringVar(&opts.tlsKeyFile, "tls-key", "", "PEM WAF-node private key (mode 0600)")
	flags.StringVar(&opts.controlServerName, "control-plane-server-name", "", "Optional control-plane TLS server SAN override")
	flags.StringVar(&opts.sidecarServerName, "sidecar-server-name", "", "Optional sidecar TLS server SAN override")
	flags.DurationVar(&opts.transportTimeout, "transport-timeout", 15*time.Second, "Timeout for each authenticated transport request")
	flags.DurationVar(&opts.operationTimeout, "operation-timeout", 2*time.Minute, "Overall asynchronous activation timeout")
	flags.BoolVar(&opts.highRisk, "high-risk", false, "Apply the high-risk signature threshold")
	flags.IntVar(&opts.observeProbes, "observe-probes", 1, "Number of observe health probes")
	flags.IntVar(&opts.canaryProbes, "canary-probes", 1, "Number of canary health probes")
	flags.DurationVar(&opts.probeTimeout, "probe-timeout", 10*time.Second, "Per-probe health timeout")
}

func runCRPActivation(cmd *cobra.Command, action crpActivationAction, opts crpActivationOptions) error {
	if err := validateCRPActivationOptions(action, opts); err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339, opts.nowText)
	if err != nil {
		return fmt.Errorf("parse --now: %w", err)
	}
	expectedRevision, err := strconv.ParseUint(opts.expectedRevisionText, 10, 64)
	if err != nil || expectedRevision == 0 {
		return errors.New("--expected-revision must be a positive integer")
	}

	// Admission is deliberately first. Trust roots and source registrations
	// are loaded and the staged/previous bytes are re-imported before checking
	// optional runtime adapters, so an invalid package cannot be hidden by a
	// missing control-plane or sidecar configuration.
	roots, err := loadTrustRoots(opts.trustRootsPath)
	if err != nil {
		return err
	}
	registrations, err := loadSourceRegistrations(opts.sourcesPath)
	if err != nil {
		return err
	}
	trust, err := crp.NewTrustStore(roots)
	if err != nil {
		return err
	}
	registry, err := crp.NewSourceRegistry(registrations)
	if err != nil {
		return err
	}
	runtimeRoot, err := filepath.Abs(opts.runtimeDir)
	if err != nil {
		return fmt.Errorf("resolve --runtime-dir: %w", err)
	}
	inspectionStore, err := newCRPActivationRuntimeStore(runtimeRoot, trust, registry, now, time.Now, opts.highRisk, nil)
	if err != nil {
		return err
	}
	record, err := selectCRPActivationRecord(inspectionStore, action, opts.pluginKey, expectedRevision)
	if err != nil {
		return err
	}
	if err := revalidateCRPRuntimeRecord(runtimeRoot, trust, registry, now, opts.highRisk, record); err != nil {
		return fmt.Errorf("verify %s runtime record: %w", action, err)
	}
	descriptor, err := loadCRPSidecarDescriptor(opts.descriptorPath)
	if err != nil {
		return err
	}
	if descriptor.PluginID != opts.pluginKey {
		return fmt.Errorf("--descriptor plugin_id %q does not match --plugin %q", descriptor.PluginID, opts.pluginKey)
	}
	manifestBytes, err := readCRPRuntimeFile(runtimeRoot, record.ManifestPath, crpStageMaxJSONBytes)
	if err != nil {
		return fmt.Errorf("read %s runtime manifest: %w", action, err)
	}
	manifest, err := crp.ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("parse %s runtime manifest: %w", action, err)
	}
	if err := activation.ValidateDescriptorManifestBinding(descriptor, manifest); err != nil {
		return err
	}

	// Transport construction happens only after local trust/source admission and
	// runtime revalidation. Missing endpoints or TLS material still fail closed,
	// but cannot hide a corrupt or revoked staged target.
	if strings.TrimSpace(opts.controlPlaneEndpoint) == "" {
		return fmt.Errorf("%w: --control-plane is required", activation.ErrControlPlaneUnavailable)
	}
	if strings.TrimSpace(opts.sidecarEndpoint) == "" {
		return fmt.Errorf("%w: --sidecar is required", activation.ErrSidecarUnavailable)
	}
	for name, value := range map[string]string{"--tls-ca": opts.tlsCAFile, "--tls-cert": opts.tlsCertFile, "--tls-key": opts.tlsKeyFile, "--node-id": opts.nodeID} {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%s is required", name)
		}
	}
	mtlsOptions := activation.MTLSOptions{
		CAFile: opts.tlsCAFile, CertFile: opts.tlsCertFile, KeyFile: opts.tlsKeyFile,
		ClusterID: opts.clusterID, NodeID: opts.nodeID, Role: "waf", Timeout: opts.transportTimeout,
		ServerName: opts.controlServerName,
	}
	controlTransport, err := activation.NewMTLSClient(mtlsOptions)
	if err != nil {
		return err
	}
	controlPlane, err := activation.NewHTTPControlPlaneClient(opts.controlPlaneEndpoint, controlTransport, time.Now)
	if err != nil {
		return fmt.Errorf("%w: %v", activation.ErrControlPlaneUnavailable, err)
	}
	runtimeAuthorizer, err := activation.NewRuntimeAuthorizer(controlPlane)
	if err != nil {
		return err
	}
	mtlsOptions.ServerName = opts.sidecarServerName
	sidecarTransport, err := activation.NewMTLSClient(mtlsOptions)
	if err != nil {
		return err
	}
	sidecars, err := activation.NewHTTPSidecarManager(opts.sidecarEndpoint, sidecarTransport, time.Now)
	if err != nil {
		return fmt.Errorf("%w: %v", activation.ErrSidecarUnavailable, err)
	}
	store, err := newCRPActivationRuntimeStore(runtimeRoot, trust, registry, now, time.Now, opts.highRisk, runtimeAuthorizer)
	if err != nil {
		return err
	}
	service, err := activation.NewService(store, activation.Options{
		Sidecars: sidecars, ControlPlane: controlPlane,
		Clock: time.Now, OperationTimeout: opts.operationTimeout,
		Policy: activation.Policy{
			AllowedCapabilities: map[string]struct{}{"observe": {}, "canary": {}},
			VerifyRecord: func(_ context.Context, candidate crp.RuntimeRecord) error {
				return revalidateCRPRuntimeRecord(runtimeRoot, trust, registry, now, opts.highRisk, candidate)
			},
		},
	})
	if err != nil {
		return err
	}
	defer service.CloseAsync()
	policy := activation.CanaryPolicy{ObserveProbes: opts.observeProbes, CanaryProbes: opts.canaryProbes, ProbeTimeout: opts.probeTimeout}
	runtimeAction := crp.RuntimeActionPromote
	if action == crpActivationActionRollback {
		runtimeAction = crp.RuntimeActionRollback
	}
	receipt, err := service.SubmitAsync(cmd.Context(), activation.AsyncRequest{Action: runtimeAction, Key: opts.pluginKey, ExpectedRevision: expectedRevision, Descriptor: descriptor, Policy: policy})
	if err != nil {
		return err
	}
	result, err := receipt.Wait(cmd.Context())
	if err != nil {
		receipt.Cancel()
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "activation_phase: %s\nplugin_key: %s\nversion: %s\nrevision: %d\nfence_epoch: %d\nfence_revision: %d\n", result.Phase, result.Record.Key, result.Record.Version, result.Record.Revision, result.Fence.Epoch, result.Fence.Revision)
	return nil
}

type crpActivationRuntimeReader interface {
	Current(string) (crp.RuntimeRecord, error)
	Staged(string) (crp.RuntimeRecord, error)
	Previous(string) (crp.RuntimeRecord, error)
}

func selectCRPActivationRecord(store crpActivationRuntimeReader, action crpActivationAction, key string, expectedRevision uint64) (crp.RuntimeRecord, error) {
	if store == nil {
		return crp.RuntimeRecord{}, crp.ErrRuntimeConfig
	}
	if action == crpActivationActionActivate {
		target, err := store.Staged(key)
		if err != nil {
			return crp.RuntimeRecord{}, err
		}
		if target.Revision != expectedRevision {
			return crp.RuntimeRecord{}, crp.ErrRuntimeConflict
		}
		return target, nil
	}
	if action != crpActivationActionRollback {
		return crp.RuntimeRecord{}, errors.New("unsupported CRP activation action")
	}
	current, err := store.Current(key)
	if err != nil {
		return crp.RuntimeRecord{}, err
	}
	if current.Revision != expectedRevision {
		return crp.RuntimeRecord{}, crp.ErrRuntimeConflict
	}
	return store.Previous(key)
}

func validateCRPActivationOptions(action crpActivationAction, opts crpActivationOptions) error {
	for name, value := range map[string]string{
		"--runtime-dir": opts.runtimeDir, "--trust-roots": opts.trustRootsPath, "--sources": opts.sourcesPath,
		"--now": opts.nowText, "--descriptor": opts.descriptorPath, "--plugin": opts.pluginKey,
		"--expected-revision": opts.expectedRevisionText, "--cluster-id": opts.clusterID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	for name, value := range map[string]string{"--plugin": opts.pluginKey, "--cluster-id": opts.clusterID} {
		if value != strings.TrimSpace(value) || !activationField(value) {
			return fmt.Errorf("%s must be a strict non-whitespace ASCII identity", name)
		}
	}
	if action != crpActivationActionActivate && action != crpActivationActionRollback {
		return errors.New("unsupported CRP activation action")
	}
	if opts.observeProbes < 1 || opts.observeProbes > crpActivationMaxProbeCount || opts.canaryProbes < 1 || opts.canaryProbes > crpActivationMaxProbeCount {
		return fmt.Errorf("probe counts must be between 1 and %d", crpActivationMaxProbeCount)
	}
	if opts.probeTimeout < 0 {
		return errors.New("--probe-timeout cannot be negative")
	}
	if opts.transportTimeout < time.Second || opts.transportTimeout > time.Minute {
		return errors.New("--transport-timeout must be between 1s and 1m")
	}
	if opts.operationTimeout < time.Second || opts.operationTimeout > 30*time.Minute {
		return errors.New("--operation-timeout must be between 1s and 30m")
	}
	return nil
}

func activationField(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}

func loadCRPSidecarDescriptor(path string) (activation.SidecarDescriptor, error) {
	data, err := readJSONFile(path)
	if err != nil {
		return activation.SidecarDescriptor{}, fmt.Errorf("read sidecar descriptor: %w", err)
	}
	var descriptor activation.SidecarDescriptor
	if err := decodeStrict(data, &descriptor); err != nil {
		return activation.SidecarDescriptor{}, fmt.Errorf("parse sidecar descriptor: %w", err)
	}
	return descriptor, nil
}

func newCRPActivationRuntimeStore(root string, trust crp.TrustStore, registry crp.SourceRegistry, verificationNow time.Time, operationClock func() time.Time, highRisk bool, authorizer crp.RuntimeAuthorizer) (*crp.RuntimeStore, error) {
	if operationClock == nil {
		operationClock = time.Now
	}
	return crp.NewRuntimeStore(root, crp.RuntimeStoreOptions{
		Clock: operationClock,
		HealthCheck: crp.HealthCheckFunc(func(record crp.RuntimeRecord) error {
			return validateCRPRuntimeRecord(root, record)
		}),
		Revalidate: crp.RuntimeRevalidateFunc(func(record crp.RuntimeRecord) error {
			return revalidateCRPRuntimeRecord(root, trust, registry, verificationNow, highRisk, record)
		}),
		Authorizer: authorizer,
	})
}
