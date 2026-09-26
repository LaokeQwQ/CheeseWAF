package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5" // #nosec G501 -- CWEDP compatibility digest.
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- CWEDP compatibility digest.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestRunServeProductionCWEDPDownloadRoute crosses the real production
// composition boundary. The peer is a real TLS listener with mandatory client
// certificates, reached through the test host's public address so the
// production PublicAddressPolicy is exercised rather than bypassed with an
// httptest or loopback transport. It intentionally requires an explicit host:
// CHEESEWAF_CWEDP_REAL_ROUTE_HOST must be a public IPv4/IPv6 address assigned
// to the test machine and reachable from that machine. The explicit high port
// must also be reachable through that address; a random port cannot establish
// whether the production public-address route is available.
func TestRunServeProductionCWEDPDownloadRoute(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	redisAddr := strings.TrimSpace(os.Getenv("CHEESEWAF_REDIS_RUNTIME_TEST_ADDR"))
	publicHost := strings.TrimSpace(os.Getenv("CHEESEWAF_CWEDP_REAL_ROUTE_HOST"))
	portText := os.Getenv("CHEESEWAF_CWEDP_REAL_ROUTE_PORT")
	if baseDSN == "" || redisAddr == "" || publicHost == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN, CHEESEWAF_REDIS_RUNTIME_TEST_ADDR, CHEESEWAF_CWEDP_REAL_ROUTE_HOST, and CHEESEWAF_CWEDP_REAL_ROUTE_PORT to run the real CWEDP route acceptance")
	}
	publicIP, err := netip.ParseAddr(publicHost)
	if err != nil || (netlease.PublicAddressPolicy{}).Allow(netlease.Target{}, publicIP) != nil {
		t.Fatalf("CHEESEWAF_CWEDP_REAL_ROUTE_HOST must be a public IP address, got %q", publicHost)
	}
	if portText == "" || strings.IndexFunc(portText, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		t.Fatal("CHEESEWAF_CWEDP_REAL_ROUTE_PORT must be a decimal port in 49152..65535")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 49152 || port > 65535 {
		t.Fatal("CHEESEWAF_CWEDP_REAL_ROUTE_PORT must be a decimal port in 49152..65535")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base, err := pgx.ParseConfig(baseDSN)
	if err != nil {
		t.Fatal("invalid PostgreSQL test DSN")
	}
	adminDB := stdlib.OpenDB(*base)
	defer adminDB.Close()
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), "-", "")
	managementSchema, controlSchema := "cw_cwedp_route_management_"+suffix, "cw_cwedp_route_control_"+suffix
	for _, schema := range []string{managementSchema, controlSchema} {
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
			t.Fatal(err)
		}
		defer func(schema string) {
			_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		}(schema)
	}

	dataRoot := t.TempDir()
	managementDSN := registerSchemaDSN(t, base, managementSchema)
	controlDSN := registerSchemaDSN(t, base, controlSchema)
	adminAddress, proxyAddress, raftAddress := reserveRunServeAddress(t), reserveRunServeAddress(t), reserveRunServeAddress(t)
	controlEndpoint, sidecarEndpoint := reserveRunServeAddress(t), reserveRunServeAddress(t)
	caPath, nodeCertPath, nodeKeyPath, serverCertPath, serverKeyPath := seedRunServeClusterTLS(t, dataRoot)
	archive, source, root, intentKey := seedRunServeCWEDPOnlineAdmission(t, dataRoot)
	peer := startRunServeCWEDPMTLSPeer(t, port, archive, caPath, serverCertPath, serverKeyPath)
	defer peer.Close()
	publicEndpoint := net.JoinHostPort(publicHost, portText)
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", publicEndpoint)
	if err != nil {
		t.Fatalf("CWEDP public route %s is unreachable before TLS: %v (the fixed acceptance port must permit public-IP return traffic)", publicEndpoint, err)
	}
	_ = connection.Close()
	configureRunServeCWEDPOnlineRegistry(t, dataRoot, publicHost, peer, source, root, caPath, nodeCertPath, nodeKeyPath)

	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileTemporary
	cfg.Storage.SQLite.Path = filepath.Join(dataRoot, "temporary.db")
	cfg.Storage.ManagementPostgreSQL.DSN, cfg.Storage.ControlPostgreSQL.DSN = managementDSN, controlDSN
	cfg.Storage.Redis.Enabled, cfg.Storage.Redis.Address, cfg.Storage.Redis.InstanceID = true, redisAddr, "runserve-cwedp-route-"+suffix
	cfg.Cluster.ClusterID, cfg.Cluster.NodeID = "runserve-cluster", "runserve-node"
	cfg.Cluster.Consensus.NativeRaft.DataDir, cfg.Cluster.Consensus.NativeRaft.Listen, cfg.Cluster.Consensus.NativeRaft.Mode = filepath.Join(dataRoot, "raft"), raftAddress, "bootstrap"
	cfg.Cluster.Interconnect.CAFile, cfg.Cluster.Interconnect.CertFile, cfg.Cluster.Interconnect.KeyFile = caPath, nodeCertPath, nodeKeyPath
	cfg.Server.Listen, cfg.Server.ListenTLS, cfg.Server.ListenHTTP3, cfg.Server.AdminListen = proxyAddress, "", "", adminAddress
	cfg.Server.AdminPublic, cfg.Server.AdminTLS.Enabled = false, false
	cfg.Setup.DataDir, cfg.Setup.RuntimeDir = dataRoot, filepath.Join(dataRoot, "run")
	cfg.TimeSync.Enabled, cfg.Console.Login.CAPTCHA.Enabled, cfg.APISec.Audit.Enabled = false, false, false
	cfg.Protection.Bot.Secret, cfg.Logging.Output.File.Path = "runserve-cwedp-route-integration-secret", filepath.Join(dataRoot, "logs", "access.log")
	seedRedisRuntimeIdentity(t, redisAddr, cfg.Storage.Redis.InstanceID)
	configFile := filepath.Join(dataRoot, "config", "cheesewaf.yaml")
	if err := config.Save(configFile, &cfg); err != nil {
		t.Fatal(err)
	}
	seedTemporaryManagement(t, ctx, cfg.Storage.SQLite.Path)
	migrate := climigration.NewRuntimeCommand(climigration.RuntimeOptions{ConfigPath: func() string { return configFile }, DataDir: func() string { return dataRoot }, AcquireExclusive: func(runtimeDir string) (io.Closer, error) { return acquirePIDLease(runtimeDir) }})
	migrate.SetArgs([]string{"temporary-to-production", "--actor", "launcher-admin", "--session-id", "launcher-temporary-session", "--password-stdin", "--language", "en-US"})
	migrate.SetIn(strings.NewReader("launcher-test-password\nCONFIRM\nyes\n"))
	migrate.SetOut(io.Discard)
	migrate.SetErr(io.Discard)
	if err := migrate.ExecuteContext(ctx); err != nil {
		t.Fatalf("temporary-to-production migration: %v", err)
	}
	if setup.NeedsSetup(dataRoot) {
		t.Fatal("migration lost completed setup state")
	}

	registryFile := seedLauncherSidecarRegistry(t)
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
	t.Setenv("CHEESEWAF_SETUP_TOKEN", "runserve-cwedp-route-setup-token")
	oldConfigPath, oldDataDir, oldFactory := configPath, dataDir, productionServeDependencyFactory
	configPath, dataDir, productionServeDependencyFactory = configFile, dataRoot, NewProductionDependencyFactory()
	t.Cleanup(func() { configPath, dataDir, productionServeDependencyFactory = oldConfigPath, oldDataDir, oldFactory })
	serveCtx, stopServe := context.WithCancel(ctx)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runServe(serveCtx) }()
	var shutdownOnce sync.Once
	stopAndWait := func() {
		shutdownOnce.Do(func() {
			stopServe()
			select {
			case err := <-serveResult:
				if err != nil {
					t.Errorf("runServe shutdown: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("runServe did not stop")
			}
		})
	}
	// This defer is registered after the schema cleanup defers above, so every
	// failure path stops the process before its PostgreSQL schemas are dropped.
	defer stopAndWait()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	baseURL := "http://" + adminAddress
	waitForRunServeRoute(t, client, baseURL+"/health/ready", serveResult)
	var epoch uint64
	if err := adminDB.QueryRowContext(ctx, `SELECT epoch FROM `+pgx.Identifier{controlSchema, "cheesewaf_controlplane_state"}.Sanitize()+` WHERE cluster_id=$1`, cfg.Cluster.ClusterID).Scan(&epoch); err != nil || epoch == 0 {
		t.Fatalf("read policy epoch: epoch=%d err=%v", epoch, err)
	}
	loginBody, _ := json.Marshal(map[string]string{"username": "launcher-admin", "password": "launcher-test-password"})
	login, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	loginRaw, _ := io.ReadAll(login.Body)
	_ = login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.StatusCode, loginRaw)
	}
	csrf, _ := runServeTemporaryHTTPBrowserCredentials(t, loginRaw, jar, baseURL)

	intent := signRunServeCWEDPIntent(t, archive, source, intentKey)
	response := runServeCWEDPRequest(t, ctx, client, baseURL, csrf, runServeCWEDPPayload(intent, epoch), http.StatusOK, dataRoot)
	var accepted struct {
		Data struct {
			JobID               string `json:"job_id"`
			Source              string `json:"source"`
			StageStatus         string `json:"stage_status"`
			PluginKey           string `json:"plugin_key"`
			Version             string `json:"version"`
			ActivationPerformed bool   `json:"activation_performed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Data.JobID == "" || accepted.Data.Source != source.ID || accepted.Data.StageStatus != string(crp.RuntimeSlotStaged) || accepted.Data.PluginKey == "" || accepted.Data.Version != "1.0.0" || accepted.Data.ActivationPerformed {
		t.Fatalf("unexpected CWEDP success response: %s", response)
	}
	if _, err := os.Stat(filepath.Join(dataRoot, "crp-runtime", "state.json")); err != nil {
		t.Fatalf("staged runtime state missing: %v", err)
	}
	auditBeforeReject := assertRunServeCWEDPAudit(t, dataRoot, publicHost, peer.Port)
	intent.Signature = "unknown-key:AAAA"
	rejected := runServeCWEDPRequest(t, ctx, client, baseURL, csrf, runServeCWEDPPayload(intent, epoch), http.StatusBadRequest, dataRoot)
	if !bytes.Contains(rejected, []byte("CWEDP_REJECTED")) {
		t.Fatalf("unsigned intent rejection body=%s", rejected)
	}
	auditAfterReject, err := os.ReadFile(filepath.Join(dataRoot, "audit", temporaryOnlineAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(auditBeforeReject, auditAfterReject) {
		t.Fatal("rejected signed-intent request issued a lease or altered persistent network audit")
	}

	stopAndWait()
}

type runServeCWEDPPeer struct {
	server   *http.Server
	listener net.Listener
	Port     int
	pin      string
}

func (p *runServeCWEDPPeer) Close() { _ = p.server.Close(); _ = p.listener.Close() }

func startRunServeCWEDPMTLSPeer(t *testing.T, port int, archive []byte, caPath, certPath, keyPath string) *runServeCWEDPPeer {
	t.Helper()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid cluster CA")
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("invalid peer certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	peerHello, _ := transport.EncodeHelloHeader(cwedp.Hello{NodeID: "control-plane", Protocol: cwedp.ProtocolVersion})
	peerCaps, _ := transport.EncodeCapabilitiesHeader(cwedp.Capabilities{NodeID: "control-plane", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: cwedp.DefaultMaxChunkBytes})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Method != http.MethodGet {
			http.Error(w, "mTLS required", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/package.crp" || r.URL.RawQuery != "" || r.Header.Get(transport.HeaderProtocol) != cwedp.ProtocolVersion {
			http.Error(w, "invalid CWEDP path or protocol", http.StatusBadRequest)
			return
		}
		hello, helloErr := transport.DecodeHelloHeader(r.Header.Get(transport.HeaderHello))
		caps, capsErr := transport.DecodeCapabilitiesHeader(r.Header.Get(transport.HeaderCapabilities))
		if helloErr != nil || capsErr != nil || hello != (cwedp.Hello{NodeID: "runserve-node", Protocol: cwedp.ProtocolVersion}) ||
			caps.NodeID != "runserve-node" || len(caps.ProtocolVersions) != 1 || caps.ProtocolVersions[0] != cwedp.ProtocolVersion ||
			len(caps.Sources) != 1 || caps.Sources[0] != cwedp.SourcePeer || caps.MaxChunkSize != cwedp.DefaultMaxChunkBytes {
			http.Error(w, "invalid CWEDP node handshake", http.StatusBadRequest)
			return
		}
		w.Header().Set(transport.HeaderPeerHello, peerHello)
		w.Header().Set(transport.HeaderPeerCaps, peerCaps)
		w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
		_, _ = w.Write(archive)
	})}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}))
	}()
	return &runServeCWEDPPeer{server: server, listener: listener, Port: port, pin: transport.CertificateFingerprint(leaf)}
}

func seedRunServeCWEDPOnlineAdmission(t *testing.T, root string) ([]byte, cwedp.Source, string, ed25519.PrivateKey) {
	t.Helper()
	publicKeys := make([]ed25519.PublicKey, 3)
	privateKeys := make([]ed25519.PrivateKey, 3)
	var err error
	for index := range privateKeys {
		publicKeys[index], privateKeys[index], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	source := cwedp.Source{Kind: cwedp.SourcePeer, ID: "cwedp-route-peer"}
	trustRoot, namespace := "cwedp-route-root", "official/cwedp-route"
	artifact := []byte("runserve-cwedp-real-route-artifact")
	manifest := crp.Manifest{APIVersion: crp.APIVersion, Kind: crp.Kind, Name: "cwedp-route", PluginID: "cwedp-route", Version: "1.0.0", Namespace: namespace, Source: source.ID, SourceRoot: trustRoot, ReleaseSequence: 1, Artifact: crp.Artifact{Name: "payload.bin", Size: int64(len(artifact)), Digests: crp.ComputeDigests(artifact)}}
	manifest.Digests = manifest.Artifact.Digests
	signatures := make([]crp.Signature, 2)
	for index := range signatures {
		signatures[index], err = crp.SignManifestWithKeyID(manifest, "cwedp-route-key-"+strconv.Itoa(index+1), privateKeys[index], time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signaturesRaw, err := json.Marshal(signatures)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, body := range map[string][]byte{"manifest.json": manifestRaw, "artifact/payload.bin": artifact, "signatures/manifest.json": signaturesRaw} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	intentPublic, intentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "cwedp")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]any{
		"sources.json":     []crp.SourceRootRegistration{{ID: trustRoot, NamespacePrefixes: []string{namespace}, Sources: []string{source.ID}}},
		"trust-roots.json": []crp.TrustRoot{{ID: trustRoot, Class: crp.SignerOfficial, NamespacePrefixes: []string{namespace}, Keys: []crp.TrustKey{{ID: "cwedp-route-key-1", PublicKey: publicKeys[0], Class: crp.SignerOfficial}, {ID: "cwedp-route-key-2", PublicKey: publicKeys[1], Class: crp.SignerOfficial}, {ID: "cwedp-route-key-3", PublicKey: publicKeys[2], Class: crp.SignerOfficial}}}},
		"intent-keys.json": productionCWEDPIntentKeysFile{Keys: []productionCWEDPIntentKey{{ID: "cwedp-route-intent", PublicKey: base64.StdEncoding.EncodeToString(intentPublic)}}},
	}
	for name, value := range files {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return archive.Bytes(), source, trustRoot, intentPrivate
}

func configureRunServeCWEDPOnlineRegistry(t *testing.T, root, publicHost string, peer *runServeCWEDPPeer, source cwedp.Source, trustRoot, caPath, certPath, keyPath string) {
	t.Helper()
	registry := productionCWEDPConfigFile{Endpoints: []productionCWEDPEndpoint{{Source: source, URL: "https://" + net.JoinHostPort(publicHost, strconv.Itoa(peer.Port)) + "/package.crp", Root: trustRoot, IndependenceGroup: "cwedp-route-peer", NodeID: "control-plane", CertificateFingerprint: peer.pin, CAFile: caPath, CertFile: certPath, KeyFile: keyPath}}}
	raw, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cwedp", "registry.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func signRunServeCWEDPIntent(t *testing.T, archive []byte, source cwedp.Source, key ed25519.PrivateKey) cwedp.DistributionIntent {
	t.Helper()
	md5sum := md5.Sum(archive)
	sha1sum := sha1.Sum(archive)
	sha256sum := sha256.Sum256(archive)
	intent := cwedp.DistributionIntent{ID: "cwedp-route-intent", PackageID: "cwedp-route", Version: "1.0.0", Size: int64(len(archive)), Digests: cwedp.Digests{MD5: hex.EncodeToString(md5sum[:]), SHA1: hex.EncodeToString(sha1sum[:]), SHA256: hex.EncodeToString(sha256sum[:])}, Sources: []cwedp.Source{source}, Signature: "placeholder"}
	payload, err := cwedp.SigningBytes(intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.Signature = "cwedp-route-intent:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return intent
}

func runServeCWEDPPayload(intent cwedp.DistributionIntent, epoch uint64) map[string]any {
	return map[string]any{"password": "launcher-test-password", "intent": intent, "hello": cwedp.Hello{NodeID: "runserve-node", Protocol: cwedp.ProtocolVersion}, "capabilities": cwedp.Capabilities{NodeID: "runserve-node", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourcePeer}, MaxChunkSize: cwedp.DefaultMaxChunkBytes}, "policy_epoch": epoch, "ttl_seconds": 20, "max_bytes": int64(1 << 20)}
}
func runServeCWEDPRequest(t *testing.T, ctx context.Context, client *http.Client, base, csrf string, payload any, want int, dataRoot string) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/system/cwedp/download", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(middleware.CSRFHeaderName, csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != want {
		if audit, auditErr := os.ReadFile(filepath.Join(dataRoot, "audit", temporaryOnlineAuditFile)); auditErr == nil {
			for _, line := range bytes.Split(bytes.TrimSpace(audit), []byte{'\n'}) {
				var event netlease.AuditEvent
				if json.Unmarshal(line, &event) == nil {
					t.Logf("CWEDP lease audit action=%q result=%q requests=%d bytes=%d", event.Action, event.Result, event.Requests, event.Bytes)
				}
			}
		} else {
			t.Logf("CWEDP lease audit unavailable: %v", auditErr)
		}
		t.Fatalf("CWEDP route status=%d want=%d body=%s", response.StatusCode, want, body)
	}
	return body
}
func assertRunServeCWEDPAudit(t *testing.T, root, host string, port int) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "audit", temporaryOnlineAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var event netlease.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.PluginID != "cwedp-route" || event.TargetHost != host || event.TargetPort != port || event.OperatorID != "launcher-admin" || !event.TemporaryEgress {
			t.Fatalf("unexpected CWEDP audit event: %+v", event)
		}
		actions[event.Action] = true
	}
	for _, action := range []string{"issued", "result", "revoked"} {
		if !actions[action] {
			t.Fatalf("CWEDP audit missing %q", action)
		}
	}
	return raw
}
