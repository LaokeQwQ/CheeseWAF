package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestRunServeProductionCRPActivationAndRollback exercises the browser-facing
// production path end to end: real runServe composition, cookie login, durable
// PostgreSQL approval submission/confirmation, authenticated CRP activation
// routes, mTLS control-plane exchange, and the process sidecar lifecycle.
// Signed packages are staged before startup because production intentionally
// exposes CRP staging through the CWEDP download workflow rather than a raw
// package-upload route. No approval record or authority-bearing claim is
// inserted directly.
func TestRunServeProductionCRPActivationAndRollback(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	redisAddr := strings.TrimSpace(os.Getenv("CHEESEWAF_REDIS_RUNTIME_TEST_ADDR"))
	registryDirectory := strings.TrimSpace(os.Getenv("CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR"))
	if baseDSN == "" || redisAddr == "" || registryDirectory == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN, CHEESEWAF_REDIS_RUNTIME_TEST_ADDR, and CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR to run the real CRP route acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	base, err := pgx.ParseConfig(baseDSN)
	if err != nil {
		t.Fatal("invalid PostgreSQL test DSN")
	}
	adminDB := stdlib.OpenDB(*base)
	t.Cleanup(func() { _ = adminDB.Close() })
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), "-", "")
	managementSchema, controlSchema := "cw_crp_route_management_"+suffix, "cw_crp_route_control_"+suffix
	for _, schema := range []string{managementSchema, controlSchema} {
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := adminDB.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
				t.Errorf("cleanup isolated CRP schema: %v", err)
			}
		})
	}

	dataRoot := t.TempDir()
	managementDSN := registerSchemaDSN(t, base, managementSchema)
	controlDSN := registerSchemaDSN(t, base, controlSchema)
	adminAddress := reserveRunServeAddress(t)
	proxyAddress := reserveRunServeAddress(t)
	raftAddress := reserveRunServeAddress(t)
	controlEndpoint := reserveRunServeAddress(t)
	sidecarEndpoint := reserveRunServeAddress(t)
	caPath, nodeCertPath, nodeKeyPath, serverCertPath, serverKeyPath := seedRunServeClusterTLS(t, dataRoot)

	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileTemporary
	cfg.Storage.SQLite.Path = filepath.Join(dataRoot, "temporary.db")
	cfg.Storage.ManagementPostgreSQL.DSN = managementDSN
	cfg.Storage.ControlPostgreSQL.DSN = controlDSN
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = redisAddr
	cfg.Storage.Redis.InstanceID = "runserve-crp-it-" + suffix
	cfg.Cluster.ClusterID = "runserve-cluster"
	cfg.Cluster.NodeID = "runserve-node"
	cfg.Cluster.Consensus.NativeRaft.DataDir = filepath.Join(dataRoot, "raft")
	cfg.Cluster.Consensus.NativeRaft.Listen = raftAddress
	cfg.Cluster.Consensus.NativeRaft.Mode = "bootstrap"
	cfg.Cluster.Interconnect.CAFile = caPath
	cfg.Cluster.Interconnect.CertFile = nodeCertPath
	cfg.Cluster.Interconnect.KeyFile = nodeKeyPath
	cfg.Server.Listen = proxyAddress
	cfg.Server.ListenTLS = ""
	cfg.Server.ListenHTTP3 = ""
	cfg.Server.AdminListen = adminAddress
	cfg.Server.AdminPublic = false
	cfg.Server.AdminTLS.Enabled = false
	cfg.Setup.DataDir = dataRoot
	cfg.Setup.RuntimeDir = filepath.Join(dataRoot, "run")
	cfg.TimeSync.Enabled = false
	cfg.Console.Login.CAPTCHA.Enabled = false
	cfg.APISec.Audit.Enabled = false
	cfg.Protection.Bot.Secret = "runserve-crp-integration-bot-secret"
	cfg.Logging.Output.File.Path = filepath.Join(dataRoot, "logs", "access.log")

	seedRedisRuntimeIdentity(t, redisAddr, cfg.Storage.Redis.InstanceID)
	configFile := filepath.Join(dataRoot, "config", "cheesewaf.yaml")
	if err := config.Save(configFile, &cfg); err != nil {
		t.Fatal(err)
	}
	seedTemporaryManagement(t, ctx, cfg.Storage.SQLite.Path)
	migrate := climigration.NewRuntimeCommand(climigration.RuntimeOptions{
		ConfigPath: func() string { return configFile }, DataDir: func() string { return dataRoot },
		AcquireExclusive: func(runtimeDir string) (io.Closer, error) { return acquirePIDLease(runtimeDir) },
	})
	migrate.SetArgs([]string{"temporary-to-production", "--actor", "launcher-admin", "--session-id", "launcher-temporary-session", "--password-stdin", "--language", "en-US"})
	migrate.SetIn(strings.NewReader("launcher-test-password\nCONFIRM\nyes\n"))
	migrate.SetOut(io.Discard)
	migrate.SetErr(io.Discard)
	if err := migrate.ExecuteContext(ctx); err != nil {
		t.Fatalf("protected temporary-to-production migration: %v", err)
	}
	if setup.NeedsSetup(dataRoot) {
		t.Fatal("migration lost the completed first-install marker")
	}

	currentV1, stagedV2 := seedRunServeCRPRuntime(t, dataRoot)
	sidecarStartMarker := filepath.Join(dataRoot, "runserve-crp-sidecar-started")
	registryFile := seedRunServeCRPSidecarRegistry(t, registryDirectory, sidecarStartMarker, currentV1, stagedV2)
	t.Setenv(EnvProductionCRPListenEndpoint, controlEndpoint)
	t.Setenv(EnvProductionCRPSidecarListenEndpoint, sidecarEndpoint)
	t.Setenv(EnvProductionCRPControlEndpoint, "https://"+controlEndpoint)
	t.Setenv(EnvProductionCRPSidecarEndpoint, "https://"+sidecarEndpoint)
	t.Setenv(EnvProductionCRPSidecarRegistryFile, registryFile)
	t.Setenv(EnvProductionCRPCAFile, caPath)
	t.Setenv(EnvProductionCRPServerCertFile, serverCertPath)
	t.Setenv(EnvProductionCRPServerKeyFile, serverKeyPath)
	t.Setenv(EnvProductionCRPClientCertFile, nodeCertPath)
	t.Setenv(EnvProductionCRPClientKeyFile, nodeKeyPath)
	t.Setenv(EnvProductionCRPControlServerName, "control-plane")
	t.Setenv(EnvProductionCRPSidecarServerName, "control-plane")
	t.Setenv("CHEESEWAF_SETUP_TOKEN", "runserve-crp-integration-setup-token")

	oldConfigPath, oldDataDir := configPath, dataDir
	oldFactory := productionServeDependencyFactory
	configPath, dataDir = configFile, dataRoot
	productionServeDependencyFactory = NewProductionDependencyFactory()
	t.Cleanup(func() {
		configPath, dataDir = oldConfigPath, oldDataDir
		productionServeDependencyFactory = oldFactory
	})
	serveCtx, stopServe := context.WithCancel(ctx)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runServe(serveCtx) }()
	var shutdownOnce sync.Once
	var shutdownErr error
	stopAndWait := func() error {
		shutdownOnce.Do(func() {
			stopServe()
			select {
			case shutdownErr = <-serveResult:
			case <-time.After(10 * time.Second):
				shutdownErr = fmt.Errorf("runServe did not stop after cancellation")
			}
		})
		return shutdownErr
	}
	t.Cleanup(func() {
		if err := stopAndWait(); err != nil {
			t.Errorf("runServe cleanup: %v", err)
		}
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	baseURL := "http://" + adminAddress
	waitForRunServeRoute(t, client, baseURL+"/health/ready", serveResult)
	csrf := runServeCRPLogin(t, ctx, client, baseURL)
	var policyEpoch uint64
	if err := adminDB.QueryRowContext(ctx, `SELECT policy_epoch FROM `+pgx.Identifier{controlSchema, "cheesewaf_approval_epoch"}.Sanitize()+` WHERE id=1`).Scan(&policyEpoch); err != nil {
		t.Fatalf("read production approval epoch: %v", err)
	}
	if policyEpoch == 0 {
		t.Fatal("production approval epoch is zero")
	}
	identity := runServeCRPTransportIdentity(t, nodeCertPath)

	promoteDescriptor := runServeCRPDescriptorForRecord(stagedV2)
	driftedDescriptor := promoteDescriptor
	driftedDescriptor.Source = "untrusted-peer"
	runServeCRPActionStatus(t, ctx, client, baseURL+"/api/system/crp/activate", csrf, stagedV2, driftedDescriptor, stagedV2.Revision, http.StatusBadRequest)
	if _, err := os.Stat(sidecarStartMarker); !os.IsNotExist(err) {
		t.Fatalf("source-mismatched descriptor started a sidecar: marker err=%v", err)
	}
	promoteRequest := runServeCRPAuthorizationRequest(t, identity, crp.RuntimeActionPromote, stagedV2, stagedV2.Revision, promoteDescriptor)
	runServeCRPApprove(t, ctx, client, baseURL, csrf, policyEpoch, promoteRequest, "runserve-crp-promote-"+suffix)
	promoted := runServeCRPAction(t, ctx, client, baseURL+"/api/system/crp/activate", csrf, stagedV2, promoteDescriptor)
	if promoted.Phase != activation.PhaseActive || promoted.Version != stagedV2.Version || promoted.ManifestIdentity != stagedV2.ManifestIdentity || promoted.Revision <= stagedV2.Revision {
		t.Fatalf("real CRP activation result=%+v, want active signed v2 %+v", promoted, stagedV2)
	}
	if _, err := os.Stat(sidecarStartMarker); err != nil {
		t.Fatalf("matching signed descriptor did not start the registered sidecar: %v", err)
	}

	rollbackDescriptor := runServeCRPDescriptorForRecord(currentV1)
	rollbackTarget := stagedV2
	rollbackTarget.Revision = promoted.Revision
	rollbackRequest := runServeCRPAuthorizationRequest(t, identity, crp.RuntimeActionRollback, currentV1, promoted.Revision, rollbackDescriptor)
	runServeCRPApprove(t, ctx, client, baseURL, csrf, policyEpoch, rollbackRequest, "runserve-crp-rollback-"+suffix)
	rolled := runServeCRPActionRevision(t, ctx, client, baseURL+"/api/system/crp/rollback", csrf, rollbackTarget, rollbackDescriptor, promoted.Revision)
	if rolled.Phase != activation.PhaseRolled || rolled.Version != currentV1.Version || rolled.ManifestIdentity != currentV1.ManifestIdentity || rolled.Revision <= promoted.Revision {
		t.Fatalf("real CRP rollback result=%+v, want exact signed v1 %+v", rolled, currentV1)
	}

	var approvedRows, auditRows int
	qualifiedApprovals := pgx.Identifier{controlSchema, "cheesewaf_approvals"}.Sanitize()
	qualifiedAudit := pgx.Identifier{controlSchema, "cheesewaf_crp_authorization_audit"}.Sanitize()
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM `+qualifiedApprovals+` WHERE record_json->>'status'='approved'`).Scan(&approvedRows); err != nil {
		t.Fatal(err)
	}
	if err := adminDB.QueryRowContext(ctx, `SELECT count(*) FROM `+qualifiedAudit+` WHERE event_json->>'operation' IN ('authorize','consume')`).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if approvedRows < 2 || auditRows < 4 {
		t.Fatalf("durable CRP evidence incomplete: approved=%d authorization_audit=%d", approvedRows, auditRows)
	}

	if err := stopAndWait(); err != nil {
		t.Fatalf("runServe shutdown: %v", err)
	}
}

type runServeCRPActionResult struct {
	Phase            activation.Phase `json:"phase"`
	PluginKey        string           `json:"plugin_key"`
	Version          string           `json:"version"`
	Revision         uint64           `json:"revision"`
	ManifestIdentity string           `json:"manifest_identity"`
}

func seedRunServeCRPRuntime(t *testing.T, dataRoot string) (crp.RuntimeRecord, crp.RuntimeRecord) {
	t.Helper()
	directory := filepath.Join(dataRoot, "cwedp")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	const rootID, sourceID, namespace = "runserve-root", "runserve-offline", "official/runserve"
	keyIDs := []string{"runserve-key-a", "runserve-key-b", "runserve-key-c"}
	trustKeys := make([]crp.TrustKey, 0, len(keyIDs))
	privateKeys := make([]ed25519.PrivateKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		trustKeys = append(trustKeys, crp.TrustKey{ID: keyID, PublicKey: publicKey, Class: crp.SignerOfficial})
		privateKeys = append(privateKeys, privateKey)
	}
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: sourceID}
	files := map[string]any{
		"registry.json":    productionCWEDPConfigFile{Endpoints: []productionCWEDPEndpoint{{Source: source, URL: "file://" + filepath.ToSlash(filepath.Join(directory, "local.crp")), Root: rootID, IndependenceGroup: "runserve-offline"}}},
		"sources.json":     []crp.SourceRootRegistration{{ID: rootID, NamespacePrefixes: []string{namespace}, Sources: []string{sourceID}}},
		"trust-roots.json": []crp.TrustRoot{{ID: rootID, Class: crp.SignerOfficial, NamespacePrefixes: []string{namespace}, Keys: trustKeys}},
		"intent-keys.json": productionCWEDPIntentKeysFile{Keys: []productionCWEDPIntentKey{{ID: "runserve-intent", PublicKey: base64.StdEncoding.EncodeToString(trustKeys[0].PublicKey)}}},
	}
	for name, value := range files {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := crp.NewSourceRegistry(files["sources.json"].([]crp.SourceRootRegistration))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := crp.NewTrustStore(files["trust-roots.json"].([]crp.TrustRoot))
	if err != nil {
		t.Fatal(err)
	}
	store, err := crp.NewRuntimeStore(filepath.Join(dataRoot, "crp-runtime"), crp.RuntimeStoreOptions{Clock: time.Now, HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }), Revalidate: crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil })})
	if err != nil {
		t.Fatal(err)
	}
	stage := func(version string, sequence uint64, artifact []byte) crp.RuntimeRecord {
		manifest := crp.Manifest{APIVersion: crp.APIVersion, Kind: crp.Kind, Name: "runserve-plugin", PluginID: "runserve-plugin", Version: version, Namespace: namespace, Source: sourceID, SourceRoot: rootID, ReleaseSequence: sequence}
		manifest.Artifact.Name, manifest.Artifact.Size = "plugin.bin", int64(len(artifact))
		manifest.Artifact.Digests = crp.ComputeDigests(artifact)
		manifest.Digests = manifest.Artifact.Digests
		signatures := make([]crp.Signature, 0, 2)
		for i := 0; i < 2; i++ {
			signature, err := crp.SignManifestWithKeyID(manifest, keyIDs[i], privateKeys[i], time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			signatures = append(signatures, signature)
		}
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		pkg := crp.Package{Manifest: raw, Artifact: artifact, Signatures: signatures}
		imported, err := crp.Import(pkg, crp.ImportOptions{SourceRegistry: registry, TrustStore: trust, Now: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		record, err := store.Stage(pkg, imported)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	v1 := stage("1.0.0", 1, []byte("runserve-crp-v1"))
	current, err := store.Promote(v1.Key, v1.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	v2 := stage("1.1.0", 2, []byte("runserve-crp-v2"))
	return current, v2
}

func seedRunServeCRPSidecarRegistry(t *testing.T, directory, startMarker string, records ...crp.RuntimeRecord) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	const executableEnvironment = "CHEESEWAF_RUNSERVE_CRP_HELPER_EXECUTABLE"
	const markerEnvironment = "CHEESEWAF_RUNSERVE_CRP_START_MARKER"
	wrapperScript := "#!/bin/sh\n: > \"$" + markerEnvironment + "\"\nexec \"$" + executableEnvironment + "\" \"$@\"\n"
	wrapperFile, err := os.CreateTemp(directory, "cheesewaf-runserve-crp-sidecar-wrapper-*")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := wrapperFile.Name()
	if _, err := wrapperFile.WriteString(wrapperScript); err != nil {
		_ = wrapperFile.Close()
		t.Fatal(err)
	}
	if err := wrapperFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wrapper, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(wrapper) })
	entries := make([]productionProcessSidecarRegistryFileEntry, 0, len(records))
	for _, record := range records {
		entries = append(entries, productionProcessSidecarRegistryFileEntry{Identity: productionProcessSidecarRegistryIdentity{PluginID: record.PluginID, Namespace: record.Namespace, Version: record.Version, ManifestIdentity: record.ManifestIdentity, ArtifactIdentity: record.ArtifactIdentity}, Executable: wrapper, Args: []string{"-test.run=^TestProductionProcessSidecarHelper$"}, WorkingDirectory: filepath.Dir(executable), Environment: map[string]string{productionProcessSidecarHelperEnvironment: "1", executableEnvironment: executable, markerEnvironment: startMarker}})
	}
	file, err := os.CreateTemp(directory, "cheesewaf-runserve-crp-sidecar-*.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	if err := json.NewEncoder(file).Encode(productionProcessSidecarRegistryFile{SchemaVersion: productionProcessSidecarRegistrySchema, Entries: entries}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

func runServeCRPDescriptorForRecord(record crp.RuntimeRecord) activation.SidecarDescriptor {
	return activation.SidecarDescriptor{
		PluginID: record.PluginID, Runtime: "sidecar", Version: record.Version,
		ManifestIdentity: record.ManifestIdentity, ArtifactIdentity: record.ArtifactIdentity,
		Namespace: record.Namespace, Source: "runserve-offline", SourceRoot: "runserve-root",
		Capabilities: []string{"observe"},
	}
}

func runServeCRPLogin(t *testing.T, ctx context.Context, client *http.Client, baseURL string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "launcher-admin", "password": "launcher-test-password"})
	response, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("real browser login status=%d body=%s", response.StatusCode, data)
	}
	var envelope struct {
		Data struct {
			CSRF string `json:"csrf"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Data.CSRF == "" {
		t.Fatalf("real browser login omitted CSRF: err=%v body=%s", err, data)
	}
	_ = ctx
	return envelope.Data.CSRF
}

func runServeCRPTransportIdentity(t *testing.T, certPath string) activation.TransportIdentity {
	t.Helper()
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("node certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cert.Raw)
	return activation.TransportIdentity{ClusterID: "runserve-cluster", NodeID: "runserve-node", Role: "waf", CertificateSHA256: hex.EncodeToString(digest[:])}
}

func runServeCRPAuthorizationRequest(t *testing.T, identity activation.TransportIdentity, action crp.RuntimeAction, target crp.RuntimeRecord, expectedRevision uint64, descriptor activation.SidecarDescriptor) activation.AuthorizationRequest {
	t.Helper()
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	permission := activation.PermissionActivate
	if action == crp.RuntimeActionRollback {
		permission = activation.PermissionRollback
	}
	return activation.AuthorizationRequest{SchemaVersion: activation.TransportSchemaVersion, RequestID: "approval-preview", Identity: identity, Action: action, Permission: permission, Target: activation.RuntimeTarget{Key: target.Key, PluginID: target.PluginID, Namespace: target.Namespace, Version: target.Version, ReleaseSequence: target.ReleaseSequence, ManifestIdentity: target.ManifestIdentity, ArtifactIdentity: target.ArtifactIdentity, Revision: target.Revision}, ExpectedRevision: expectedRevision, Descriptor: descriptor, DescriptorIdentity: hex.EncodeToString(digest[:]), Canary: activation.CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1, ProbeTimeout: time.Second}, RequestedAt: time.Now().UTC()}
}

func runServeCRPApprove(t *testing.T, ctx context.Context, client *http.Client, baseURL, csrf string, epoch uint64, request activation.AuthorizationRequest, id string) {
	t.Helper()
	submit := map[string]any{"id": id, "risk": string(approval.RiskMedium), "scope": activation.ApprovalScope(request), "policy_epoch": epoch, "ttl": "2m", "confirmation_language": "en-US", "intent_digest": activation.ApprovalIntentDigest(request), "nonce": "nonce-" + id}
	var submitted struct {
		Record approval.Record `json:"record"`
	}
	runServeCRPJSON(t, ctx, client, http.MethodPost, baseURL+"/api/approvals", csrf, submit, http.StatusOK, &submitted)
	if submitted.Record.ID != id || submitted.Record.Status != approval.StatusPending {
		t.Fatalf("approval submission mismatch: %+v", submitted.Record)
	}
	var started struct {
		Challenge struct {
			ConfirmationID string `json:"confirmation_id"`
			Phrase         string `json:"phrase"`
		} `json:"challenge"`
	}
	runServeCRPJSON(t, ctx, client, http.MethodPost, baseURL+"/api/approvals/"+id+"/confirmation/start", csrf, map[string]string{"language": "en-US"}, http.StatusOK, &started)
	if started.Challenge.ConfirmationID == "" || started.Challenge.Phrase == "" {
		t.Fatal("approval confirmation challenge is incomplete")
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(approval.WarningDelay):
	}
	checkpoint := map[string]any{"confirmation_id": started.Challenge.ConfirmationID, "confirmation_phrase": started.Challenge.Phrase, "password": "launcher-test-password", "second_confirmation": true}
	var confirmed struct {
		Record approval.Record `json:"record"`
	}
	runServeCRPJSON(t, ctx, client, http.MethodPost, baseURL+"/api/approvals/"+id+"/confirmation", csrf, checkpoint, http.StatusOK, &confirmed)
	if confirmed.Record.Status != approval.StatusApproved || confirmed.Record.Commit == nil {
		t.Fatalf("approval was not durably authorized: %+v", confirmed.Record)
	}
}

func runServeCRPAction(t *testing.T, ctx context.Context, client *http.Client, url, csrf string, record crp.RuntimeRecord, descriptor activation.SidecarDescriptor) runServeCRPActionResult {
	return runServeCRPActionRevision(t, ctx, client, url, csrf, record, descriptor, record.Revision)
}

func runServeCRPActionRevision(t *testing.T, ctx context.Context, client *http.Client, url, csrf string, record crp.RuntimeRecord, descriptor activation.SidecarDescriptor, revision uint64) runServeCRPActionResult {
	t.Helper()
	payload := map[string]any{"plugin_key": record.Key, "expected_revision": revision, "descriptor": descriptor, "observe_probes": 1, "canary_probes": 1, "probe_timeout_seconds": 1}
	var result runServeCRPActionResult
	runServeCRPJSON(t, ctx, client, http.MethodPost, url, csrf, payload, http.StatusOK, &result)
	return result
}

func runServeCRPActionStatus(t *testing.T, ctx context.Context, client *http.Client, url, csrf string, record crp.RuntimeRecord, descriptor activation.SidecarDescriptor, revision uint64, wantStatus int) {
	t.Helper()
	payload := map[string]any{"plugin_key": record.Key, "expected_revision": revision, "descriptor": descriptor, "observe_probes": 1, "canary_probes": 1, "probe_timeout_seconds": 1}
	runServeCRPJSON(t, ctx, client, http.MethodPost, url, csrf, payload, wantStatus, nil)
}

func runServeCRPJSON(t *testing.T, ctx context.Context, client *http.Client, method, url, csrf string, payload any, wantStatus int, data any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != wantStatus {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, url, response.StatusCode, wantStatus, raw)
	}
	if data == nil || wantStatus < 200 || wantStatus >= 300 {
		return
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode API envelope: %v body=%s", err, raw)
	}
	if err := json.Unmarshal(envelope.Data, data); err != nil {
		t.Fatalf("decode API data: %v body=%s", err, raw)
	}
}
