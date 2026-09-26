package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
	clusteridentity "github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestRunServeProductionRealListenerAndSessionRoute is an opt-in deployment
// acceptance that crosses the process composition boundary deliberately. It
// migrates isolated management state into PostgreSQL, starts runServe with the
// real PostgreSQL/Redis/native-raft/CRP dependencies, and reaches the admin
// router through a loopback TCP listener. No httptest server or captured
// ProductionServeWiring is used.
func TestRunServeProductionRealListenerAndSessionRoute(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	redisAddr := strings.TrimSpace(os.Getenv("CHEESEWAF_REDIS_RUNTIME_TEST_ADDR"))
	if baseDSN == "" || redisAddr == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN and CHEESEWAF_REDIS_RUNTIME_TEST_ADDR to run the real runServe acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
	managementSchema := "cw_runserve_management_" + suffix
	controlSchema := "cw_runserve_control_" + suffix
	for _, schema := range []string{managementSchema, controlSchema} {
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") }()
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
	cfg.Storage.Redis.InstanceID = "runserve-it-" + suffix
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
	cfg.Protection.Bot.Secret = "runserve-integration-bot-secret-32-bytes"
	cfg.Logging.Output.File.Path = filepath.Join(dataRoot, "logs", "access.log")

	seedRedisRuntimeIdentity(t, redisAddr, cfg.Storage.Redis.InstanceID)
	configFile := filepath.Join(dataRoot, "config", "cheesewaf.yaml")
	if err := config.Save(configFile, &cfg); err != nil {
		t.Fatal(err)
	}
	seedTemporaryManagement(t, ctx, cfg.Storage.SQLite.Path)
	temporarySessionToken := seedLauncherTemporaryBrowserSession(t, ctx, cfg.Storage.SQLite.Path, dataRoot)
	migrate := climigration.NewRuntimeCommand(climigration.RuntimeOptions{
		ConfigPath: func() string { return configFile },
		DataDir:    func() string { return dataRoot },
		AcquireExclusive: func(runtimeDir string) (io.Closer, error) {
			return acquirePIDLease(runtimeDir)
		},
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
	seedLauncherCWEDPAdmission(t, dataRoot)

	// The process-sidecar registry rejects world-writable ancestors, including
	// /tmp on a typical deployment host. The opt-in integration environment
	// supplies a secure parent for the short-lived allowlist file.
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
	t.Setenv("CHEESEWAF_SETUP_TOKEN", "runserve-integration-setup-token")

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
	t.Cleanup(stopServe)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	baseURL := "http://" + adminAddress
	waitForRunServeRoute(t, client, baseURL+"/health/ready", serveResult)
	if _, err := os.Stat(filepath.Join(dataRoot, setup.URLFileName)); !os.IsNotExist(err) {
		t.Fatalf("production runServe issued a first-install URL after migration: %v", err)
	}

	statusResponse, err := client.Get(baseURL + "/api/setup/status")
	if err != nil {
		t.Fatalf("real setup-status route: %v", err)
	}
	statusBody, _ := io.ReadAll(statusResponse.Body)
	_ = statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK || !bytes.Contains(statusBody, []byte(`"needs_setup":false`)) {
		t.Fatalf("real setup-status route status=%d body=%s", statusResponse.StatusCode, statusBody)
	}
	probeResponse, err := client.Post(baseURL+"/api/setup/probe", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("real setup-probe route: %v", err)
	}
	probeBody, _ := io.ReadAll(probeResponse.Body)
	_ = probeResponse.Body.Close()
	if probeResponse.StatusCode != http.StatusConflict || !bytes.Contains(probeBody, []byte("SETUP_ALREADY_COMPLETE")) {
		t.Fatalf("migrated setup-probe route status=%d body=%s", probeResponse.StatusCode, probeBody)
	}
	oldSessionRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldSessionRequest.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: temporarySessionToken})
	oldSessionResponse, err := client.Do(oldSessionRequest)
	if err != nil {
		t.Fatalf("real invalidated temporary-session route: %v", err)
	}
	_, _ = io.Copy(io.Discard, oldSessionResponse.Body)
	_ = oldSessionResponse.Body.Close()
	if oldSessionResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("real invalidated temporary-session route status=%d, want 401", oldSessionResponse.StatusCode)
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "launcher-admin", "password": "launcher-test-password"})
	loginResponse, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("real login route: %v", err)
	}
	loginResponseBody, _ := io.ReadAll(loginResponse.Body)
	_ = loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("real login route status=%d body=%s", loginResponse.StatusCode, loginResponseBody)
	}

	sessionRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	sessionResponse, err := client.Do(sessionRequest)
	if err != nil {
		t.Fatalf("real session route: %v", err)
	}
	sessionBody, _ := io.ReadAll(sessionResponse.Body)
	_ = sessionResponse.Body.Close()
	if sessionResponse.StatusCode != http.StatusOK || !bytes.Contains(sessionBody, []byte(`"username":"launcher-admin"`)) {
		t.Fatalf("real session route status=%d body=%s", sessionResponse.StatusCode, sessionBody)
	}

	stopServe()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("runServe shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runServe did not stop after cancellation")
	}
}

func seedLauncherTemporaryBrowserSession(t *testing.T, ctx context.Context, dbPath, dataRoot string) string {
	t.Helper()
	secret, err := ensureAuthSecret(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user := loadLauncherUserFixture(t, ctx, store)
	manager := middleware.NewTokenManager(secret, time.Hour)
	token, claims, err := manager.SignWithClaims(user.ID, user.Username, user.Role)
	if err != nil {
		t.Fatal(err)
	}
	persistLauncherSessionFixture(t, ctx, store, user, claims)
	return token
}

func reserveRunServeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func seedRunServeClusterTLS(t *testing.T, root string) (string, string, string, string, string) {
	t.Helper()
	identityService, err := clusteridentity.NewMemoryIdentityService(clusteridentity.ServiceOptions{ClusterID: "runserve-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	nodeBundle, err := identityService.IssueNodeCertificateBundle(clusteridentity.NodeIdentity{
		NodeID: "runserve-node", Role: "waf", ClusterID: "runserve-cluster", AdvertiseAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	serverBundle, err := identityService.IssueNodeCertificateBundle(clusteridentity.NodeIdentity{
		NodeID: "control-plane", Role: "monitor", ClusterID: "runserve-cluster", AdvertiseAddr: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "cluster")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []struct {
		name string
		data []byte
	}{
		{"ca.pem", nodeBundle.CAPEM},
		{"node.crt", nodeBundle.CertPEM},
		{"node.key", nodeBundle.KeyPEM},
		{"control.crt", serverBundle.CertPEM},
		{"control.key", serverBundle.KeyPEM},
	}
	for _, item := range paths {
		if err := os.WriteFile(filepath.Join(directory, item.name), item.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(directory, "ca.pem"), filepath.Join(directory, "node.crt"), filepath.Join(directory, "node.key"), filepath.Join(directory, "control.crt"), filepath.Join(directory, "control.key")
}

func waitForRunServeRoute(t *testing.T, client *http.Client, url string, serveResult <-chan error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serveResult:
			t.Fatalf("runServe exited before listener became ready: %v", err)
		default:
		}
		response, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("real runServe route %s did not become ready", url)
}
