package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

// TestProductionLauncherPostgresCutoverAndSessionInvalidation is an opt-in
// deployment-level acceptance. It opens the real production dependency
// factory (PostgreSQL management/control stores, native-raft TLS, Redis,
// approval runtime, and temporary-network provider), then drives the same
// durable session validator handed to the serving layer. The test is skipped
// unless both real PostgreSQL and Redis endpoints are explicitly supplied.
//
// The test owns two random PostgreSQL schemas and only seeds a namespaced
// Redis identity key. It never truncates or drops objects outside those
// namespaces.
func TestProductionLauncherPostgresCutoverAndSessionInvalidation(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	redisAddr := strings.TrimSpace(os.Getenv("CHEESEWAF_REDIS_RUNTIME_TEST_ADDR"))
	if baseDSN == "" || redisAddr == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN and CHEESEWAF_REDIS_RUNTIME_TEST_ADDR to run the real production launcher acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	base, err := pgx.ParseConfig(baseDSN)
	if err != nil {
		t.Fatal("invalid PostgreSQL test DSN")
	}
	admin := stdlib.OpenDB(*base)
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	managementSchema := "cw_launcher_management_" + strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), "-", "")
	controlSchema := "cw_launcher_control_" + strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()+1), "-", "")
	for _, schema := range []string{managementSchema, controlSchema} {
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") }()
	}
	managementDSN := registerSchemaDSN(t, base, managementSchema)
	controlDSN := registerSchemaDSN(t, base, controlSchema)

	dataDir := t.TempDir()
	identityService, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "launcher-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := identityService.IssueNodeCertificateBundle(identity.NodeIdentity{
		NodeID: "launcher-node", Role: "waf", ClusterID: "launcher-cluster", AdvertiseAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsDir := filepath.Join(dataDir, "cluster")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(tlsDir, "ca.pem")
	certPath := filepath.Join(tlsDir, "node.crt")
	keyPath := filepath.Join(tlsDir, "node.key")
	for _, item := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{caPath, bundle.CAPEM, 0o600}, {certPath, bundle.CertPEM, 0o600}, {keyPath, bundle.KeyPEM, 0o600}} {
		if err := os.WriteFile(item.path, item.data, item.mode); err != nil {
			t.Fatal(err)
		}
	}
	serverBundle, err := identityService.IssueNodeCertificateBundle(identity.NodeIdentity{
		NodeID: "control-plane", Role: "monitor", ClusterID: "launcher-cluster", AdvertiseAddr: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCertPath := filepath.Join(tlsDir, "control.crt")
	serverKeyPath := filepath.Join(tlsDir, "control.key")
	if err := os.WriteFile(serverCertPath, serverBundle.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverKeyPath, serverBundle.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileTemporary
	cfg.Storage.SQLite.Path = filepath.Join(dataDir, "temporary.db")
	cfg.Storage.ManagementPostgreSQL.DSN = managementDSN
	cfg.Storage.ControlPostgreSQL.DSN = controlDSN
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = redisAddr
	cfg.Storage.Redis.InstanceID = "launcher-it-" + strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), "-", "")
	cfg.Cluster.ClusterID = "launcher-cluster"
	cfg.Cluster.NodeID = "launcher-node"
	cfg.Cluster.Consensus.NativeRaft.DataDir = filepath.Join(dataDir, "raft")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Cluster.Consensus.NativeRaft.Listen = listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Cluster.Consensus.NativeRaft.Mode = "bootstrap"
	cfg.Cluster.Interconnect.CAFile = caPath
	cfg.Cluster.Interconnect.CertFile = certPath
	cfg.Cluster.Interconnect.KeyFile = keyPath
	cfg.Setup.DataDir = dataDir
	cfg.Setup.RuntimeDir = filepath.Join(dataDir, "run")

	seedRedisRuntimeIdentity(t, redisAddr, cfg.Storage.Redis.InstanceID)
	configPath := filepath.Join(dataDir, "config", "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatal(err)
	}
	seedTemporaryManagement(t, ctx, cfg.Storage.SQLite.Path)
	command := climigration.NewRuntimeCommand(climigration.RuntimeOptions{
		ConfigPath: func() string { return configPath },
		DataDir:    func() string { return dataDir },
		AcquireExclusive: func(runtimeDir string) (io.Closer, error) {
			return acquirePIDLease(runtimeDir)
		},
	})
	command.SetArgs([]string{"temporary-to-production", "--actor", "launcher-admin", "--session-id", "launcher-temporary-session", "--password-stdin", "--language", "en-US"})
	command.SetIn(strings.NewReader("launcher-test-password\nCONFIRM\nyes\n"))
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	if err := command.ExecuteContext(ctx); err != nil {
		t.Fatalf("protected temporary-to-production migration: %v", err)
	}
	productionCfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if productionCfg.Storage.Profile != config.StorageProfileProduction {
		t.Fatalf("migration did not publish production profile: %q", productionCfg.Storage.Profile)
	}
	cfg = *productionCfg
	seedLauncherCWEDPAdmission(t, dataDir)

	opts, err := productionStartupOptionsFromConfig(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := seedLauncherSidecarRegistry(t)
	controlEndpoint := reserveProductionCRPAddress(t)
	sidecarEndpoint := reserveProductionCRPAddress(t)
	for sidecarEndpoint == controlEndpoint {
		sidecarEndpoint = reserveProductionCRPAddress(t)
	}
	opts.CRP = ProductionCRPOptions{
		ListenEndpoint: controlEndpoint, SidecarListenEndpoint: sidecarEndpoint,
		ControlEndpoint: "https://" + controlEndpoint, SidecarEndpoint: "https://" + sidecarEndpoint,
		CAFile: caPath, ServerCertFile: serverCertPath, ServerKeyFile: serverKeyPath,
		ClientCertFile: certPath, ClientKeyFile: keyPath,
		ControlServerName: "control-plane", SidecarServerName: "control-plane",
		SidecarRegistryFile: registryPath,
	}
	var wired ProductionServeWiring
	factory := NewProductionDependencyFactory()
	factory.WireServeWithWiring = func(_ context.Context, next ProductionServeWiring) error {
		wired = next
		return nil
	}
	deps, err := OpenProductionDependencies(ctx, opts, factory)
	if err != nil {
		t.Fatalf("real production dependency startup: %v", err)
	}
	t.Cleanup(func() { _ = deps.Close() })
	if !deps.Ready || wired.ManagementStore == nil || wired.SessionValidator == nil {
		t.Fatalf("production launcher did not publish ready management/session wiring: ready=%t store=%T validator=%T", deps.Ready, wired.ManagementStore, wired.SessionValidator)
	}
	handoff, err := climigration.ValidateProductionHandoff(dataDir, &cfg)
	if err != nil {
		t.Fatalf("production handoff validation: %v", err)
	}
	verifier, ok := wired.ManagementStore.(storage.MigrationHandoffVerifier)
	if !ok {
		t.Fatal("running launcher management store does not expose migration handoff verification")
	}
	if err := verifier.VerifyMigrationHandoff(ctx, handoff.Evidence()); err != nil {
		t.Fatalf("running launcher rejected durable cutover evidence: %v", err)
	}
	if active, err := wired.SessionValidator.IsSessionActive(ctx, "launcher-temporary-session", "launcher-admin", time.Now().UTC()); err != nil || active {
		t.Fatalf("temporary session remained active after cutover: active=%t err=%v", active, err)
	}

	user := loadLauncherUserFixture(t, ctx, wired.ManagementStore)
	manager := middleware.NewTokenManager("launcher-session-test-secret", time.Hour)
	token, claims, err := manager.SignWithClaims(user.ID, user.Username, user.Role)
	if err != nil {
		t.Fatal(err)
	}
	session := persistLauncherSessionFixture(t, ctx, wired.ManagementStore, user, claims)
	protected := manager.Middleware(middleware.SessionMiddleware(wired.SessionValidator)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "http://launcher.invalid/api/auth/session", nil)
		req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: token})
		recorder := httptest.NewRecorder()
		protected.ServeHTTP(recorder, req)
		return recorder.Code
	}
	if got := request(); got != http.StatusNoContent {
		t.Fatalf("running launcher rejected active PostgreSQL session: status=%d", got)
	}
	// Opt-in deployment probe: a real public HTTPS HEAD request must be bound
	// to the migrated PostgreSQL session, its password, the startup epoch, and
	// the exact pinned leaf certificate. The target is fixed to example.com so
	// test configuration cannot turn the production broker into an arbitrary
	// outbound client. Only the operator-supplied public certificate pin varies.
	publicPin := os.Getenv("CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN")
	var publicAuditBeforeRevocation []byte
	if publicPin != "" {
		if err := netlease.ValidateTLSFingerprint(publicPin); err != nil {
			t.Fatalf("invalid public test certificate pin: %v", err)
		}
		probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
		publicRequest := launcherPublicNetworkRequest(user.ID, session.ID, wired.PolicyEpoch, publicPin)
		response, err := wired.TemporaryHTTPExecutor.ExecuteTemporaryHTTP(probeCtx, publicRequest)
		probeCancel()
		if err != nil {
			t.Fatalf("real production temporary-network request: %v", err)
		}
		if response.StatusCode != http.StatusOK || response.TLSFingerprint != publicPin || len(response.Body) != 0 || response.RemoteAddress == "" {
			t.Fatalf("real production temporary-network response: status=%d pin_match=%t body_length=%d remote_present=%t", response.StatusCode, response.TLSFingerprint == publicPin, len(response.Body), response.RemoteAddress != "")
		}
		publicAuditBeforeRevocation = readLauncherPublicNetworkAudit(t, dataDir, publicPin)
		t.Logf("production temporary-network real HTTPS: status=%d pinned=true audit=issued,result,revoked", response.StatusCode)
	}
	if err := wired.ManagementStore.RevokeUserSessions(ctx, user.ID, ""); err != nil {
		t.Fatalf("durable session invalidation: %v", err)
	}
	if got := request(); got != http.StatusUnauthorized {
		t.Fatalf("running launcher accepted invalidated PostgreSQL session: status=%d", got)
	}
	if active, err := wired.SessionValidator.IsSessionActive(ctx, session.ID, user.ID, time.Now().UTC()); err != nil || active {
		t.Fatalf("durable session state active=%t err=%v after invalidation", active, err)
	}
	if publicPin != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := wired.TemporaryHTTPExecutor.ExecuteTemporaryHTTP(probeCtx, launcherPublicNetworkRequest(user.ID, session.ID, wired.PolicyEpoch, publicPin))
		probeCancel()
		if !errors.Is(err, netlease.ErrAdministratorSessionDenied) {
			t.Fatalf("revoked PostgreSQL session temporary-network error=%v, want session denial", err)
		}
		auditAfter, err := os.ReadFile(filepath.Join(dataDir, "audit", temporaryOnlineAuditFile))
		if err != nil {
			t.Fatal(err)
		}
		if string(auditAfter) != string(publicAuditBeforeRevocation) {
			t.Fatal("revoked PostgreSQL session issued a new network capability or changed durable network audit")
		}
		t.Log("revoked PostgreSQL session denied temporary network before lease issuance")
	}
}

func launcherPublicNetworkRequest(userID, sessionID string, epoch uint64, pin string) netlease.TemporaryHTTPExecution {
	return netlease.TemporaryHTTPExecution{
		Identity:         netlease.AdministratorIdentity{ID: userID, ManagementSessionID: sessionID},
		Password:         "launcher-test-password",
		PluginID:         "launcher-public-test",
		PluginVersion:    "1.0.0",
		Target:           netlease.Target{Host: "example.com", Port: 443, Protocol: "https"},
		TLSFingerprint:   pin,
		PolicyEpoch:      epoch,
		TTL:              20 * time.Second,
		MaxBytes:         16 << 10,
		Method:           http.MethodHead,
		Path:             "/",
		MaxResponseBytes: 1024,
	}
}

func readLauncherPublicNetworkAudit(t *testing.T, dataDir, pin string) []byte {
	t.Helper()
	audit, err := os.ReadFile(filepath.Join(dataDir, "audit", temporaryOnlineAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), "launcher-test-password") {
		t.Fatal("temporary-network audit exposed the administrator password")
	}
	actions := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var event netlease.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode temporary-network audit: %v", err)
		}
		if event.PluginID != "launcher-public-test" || event.TargetHost != "example.com" || event.TargetPort != 443 || event.OperatorID != "launcher-admin" || event.TLSFingerprint != pin || !event.TemporaryEgress {
			t.Fatalf("temporary-network audit identity or target mismatch: action=%q", event.Action)
		}
		if event.Action == "result" && (event.Result != "http_200" || event.Requests != 1 || event.Bytes <= 0) {
			t.Fatalf("temporary-network audit has no successful one-shot request: result=%q requests=%d bytes=%d", event.Result, event.Requests, event.Bytes)
		}
		actions[event.Action] = true
	}
	for _, action := range []string{"issued", "result", "revoked"} {
		if !actions[action] {
			t.Fatalf("temporary-network audit missing %q event", action)
		}
	}
	return audit
}

func seedLauncherSidecarRegistry(t *testing.T) string {
	t.Helper()
	directory := strings.TrimSpace(os.Getenv("CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR"))
	if directory == "" {
		t.Fatal("CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR is required when the real launcher integration is enabled")
	}
	file, err := os.CreateTemp(directory, "cheesewaf-launcher-sidecar-*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	if _, err := file.Write(productionProcessSidecarRegistryJSON(t)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedLauncherCWEDPAdmission(t *testing.T, dataDir string) {
	t.Helper()
	directory := filepath.Join(dataDir, "cwedp")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "launcher-local-source"}
	root := "launcher-community-root"
	namespace := "community/launcher/"
	files := map[string]any{
		"registry.json": productionCWEDPConfigFile{Endpoints: []productionCWEDPEndpoint{{
			Source: source, URL: "file://" + filepath.ToSlash(filepath.Join(directory, "local.crp")),
			Root: root, IndependenceGroup: "launcher-offline",
		}}},
		"sources.json": []crp.SourceRootRegistration{{
			ID: root, NamespacePrefixes: []string{namespace}, Sources: []string{source.ID},
		}},
		"trust-roots.json": []crp.TrustRoot{{
			ID: root, Class: crp.SignerCommunity, NamespacePrefixes: []string{namespace},
			Keys: []crp.TrustKey{{ID: "launcher-key", PublicKey: publicKey}},
		}},
		"intent-keys.json": productionCWEDPIntentKeysFile{Keys: []productionCWEDPIntentKey{{
			ID: "launcher-intent", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}}},
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
}

func registerSchemaDSN(t *testing.T, base *pgx.ConnConfig, schema string) string {
	t.Helper()
	clone := base.Copy()
	if clone.RuntimeParams == nil {
		clone.RuntimeParams = map[string]string{}
	} else {
		params := make(map[string]string, len(clone.RuntimeParams))
		for key, value := range clone.RuntimeParams {
			params[key] = value
		}
		clone.RuntimeParams = params
	}
	clone.RuntimeParams["search_path"] = schema
	return stdlib.RegisterConnConfig(clone)
}

func seedTemporaryManagement(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	store, err := storage.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("launcher-test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user := &storage.User{ID: "launcher-admin", Username: "launcher-admin", PasswordHash: string(hash), Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, &storage.Session{ID: "launcher-temporary-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// The source is an already-installed temporary instance, not a database
	// seeded before its first-install transaction finished.
	if err := setup.MarkComplete(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
}

func loadLauncherUserFixture(t *testing.T, ctx context.Context, store storage.Store) storage.User {
	t.Helper()
	users, err := store.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("load launcher user: users=%d err=%v", len(users), err)
	}
	return users[0]
}

func persistLauncherSessionFixture(t *testing.T, ctx context.Context, store storage.Store, user storage.User, claims *middleware.Claims) storage.Session {
	t.Helper()
	session := &storage.Session{
		ID: claims.ID, UserID: user.ID, Username: user.Username, Role: user.Role,
		CredentialEpoch: user.CredentialEpoch, IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(claims.Expires, 0).UTC(),
	}
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("create post-cutover session: %v", err)
	}
	lookup, ok := store.(storage.SessionLookupStore)
	if !ok {
		t.Fatalf("launcher store does not expose session lookup: %T", store)
	}
	session, err := lookup.GetSession(ctx, session.ID, user.ID)
	if err != nil || session == nil {
		t.Fatalf("load launcher session: session=%+v err=%v", session, err)
	}
	return *session
}

func seedRedisRuntimeIdentity(t *testing.T, addr, instanceID string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	key := "cheesewaf:runtime:instance_id"
	if _, err := fmt.Fprintf(conn, "*5\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n$2\r\nPX\r\n$5\r\n60000\r\n", len(key), key, len(instanceID), instanceID); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, err := conn.Read(buffer); err != nil {
		t.Fatal(err)
	}
}
