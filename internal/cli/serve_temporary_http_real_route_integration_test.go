package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	climigration "github.com/LaokeQwQ/CheeseWAF/internal/cli/migration"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestRunServeProductionTemporaryHTTPRoute drives the exposed management route
// through the real runServe listener. It deliberately does not call the
// provider directly: the assertion includes browser-session authentication,
// CSRF, durable PostgreSQL session invalidation, a pinned public HTTPS request,
// and the runtime-owned lease audit.
func TestRunServeProductionTemporaryHTTPRoute(t *testing.T) {
	baseDSN := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	redisAddr := strings.TrimSpace(os.Getenv("CHEESEWAF_REDIS_RUNTIME_TEST_ADDR"))
	publicPin := strings.TrimSpace(os.Getenv("CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN"))
	if baseDSN == "" || redisAddr == "" || publicPin == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN, CHEESEWAF_REDIS_RUNTIME_TEST_ADDR, and CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN to run the real temporary-http route acceptance")
	}
	if err := netlease.ValidateTLSFingerprint(publicPin); err != nil {
		t.Fatalf("invalid CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN: %v", err)
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
	managementSchema := "cw_runserve_temporary_http_management_" + suffix
	controlSchema := "cw_runserve_temporary_http_control_" + suffix
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
	adminAddress := reserveRunServeAddress(t)
	proxyAddress := reserveRunServeAddress(t)
	raftAddress := reserveRunServeAddress(t)
	controlEndpoint := reserveRunServeAddress(t)
	sidecarEndpoint := reserveRunServeAddress(t)
	for sidecarEndpoint == controlEndpoint {
		sidecarEndpoint = reserveRunServeAddress(t)
	}

	caPath, nodeCertPath, nodeKeyPath, serverCertPath, serverKeyPath := seedRunServeClusterTLS(t, dataRoot)
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileTemporary
	cfg.Storage.SQLite.Path = filepath.Join(dataRoot, "temporary.db")
	cfg.Storage.ManagementPostgreSQL.DSN = managementDSN
	cfg.Storage.ControlPostgreSQL.DSN = controlDSN
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = redisAddr
	cfg.Storage.Redis.InstanceID = "runserve-temporary-http-it-" + suffix
	// The shared cluster TLS fixture signs these exact cluster/node identities.
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
	cfg.Protection.Bot.Secret = "runserve-temporary-http-integration-bot-secret-32-bytes"
	cfg.Logging.Output.File.Path = filepath.Join(dataRoot, "logs", "access.log")

	seedRedisRuntimeIdentity(t, redisAddr, cfg.Storage.Redis.InstanceID)
	configFile := filepath.Join(dataRoot, "config", "cheesewaf.yaml")
	if err := config.Save(configFile, &cfg); err != nil {
		t.Fatal(err)
	}
	seedTemporaryManagement(t, ctx, cfg.Storage.SQLite.Path)
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
	t.Setenv("CHEESEWAF_SETUP_TOKEN", "runserve-temporary-http-integration-setup-token")

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
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	baseURL := "http://" + adminAddress
	waitForRunServeRoute(t, client, baseURL+"/health/ready", serveResult)
	var policyEpoch int64
	if err := adminDB.QueryRowContext(ctx, `SELECT epoch FROM `+pgx.Identifier{controlSchema, "cheesewaf_controlplane_state"}.Sanitize()+` WHERE cluster_id=$1`, cfg.Cluster.ClusterID).Scan(&policyEpoch); err != nil || policyEpoch <= 0 {
		t.Fatalf("load running control-plane policy epoch: epoch=%d err=%v", policyEpoch, err)
	}
	t.Logf("running control-plane policy epoch=%d", policyEpoch)

	loginBody, _ := json.Marshal(map[string]string{"username": "launcher-admin", "password": "launcher-test-password"})
	loginResponse, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("real temporary-http login route: %v", err)
	}
	loginResponseBody, _ := io.ReadAll(loginResponse.Body)
	_ = loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("real temporary-http login route status=%d body=%s", loginResponse.StatusCode, loginResponseBody)
	}
	csrf, sessionCookie := runServeTemporaryHTTPBrowserCredentials(t, loginResponseBody, jar, baseURL)

	payload := runServeTemporaryHTTPPayload(publicPin, uint64(policyEpoch))
	responseBody := runServeTemporaryHTTPRequest(t, client, baseURL+"/api/system/temporary-http", payload, csrf, nil)
	var response struct {
		Data struct {
			StatusCode     int    `json:"status_code"`
			TLSFingerprint string `json:"tls_fingerprint"`
			RemoteAddress  string `json:"remote_address"`
		} `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("decode temporary-http route response: %v body=%s", err, responseBody)
	}
	if response.Data.StatusCode != http.StatusOK || response.Data.TLSFingerprint != publicPin || response.Data.RemoteAddress == "" {
		t.Fatalf("temporary-http route response status=%d pin_match=%t remote_present=%t", response.Data.StatusCode, response.Data.TLSFingerprint == publicPin, response.Data.RemoteAddress != "")
	}
	auditBeforeLogout := assertRunServeTemporaryHTTPAudit(t, dataRoot, publicPin)

	logoutResponseBody := runServeTemporaryHTTPRequest(t, client, baseURL+"/api/auth/logout", nil, csrf, nil)
	if !bytes.Contains(logoutResponseBody, []byte(`"revoked":true`)) {
		t.Fatalf("logout route did not acknowledge session revocation: %s", logoutResponseBody)
	}

	staleCookie := &http.Cookie{Name: middleware.SessionCookieName, Value: sessionCookie, Path: "/"}
	staleResponseBody := runServeTemporaryHTTPRequest(t, &http.Client{Timeout: 5 * time.Second}, baseURL+"/api/system/temporary-http", payload, csrf, []*http.Cookie{staleCookie, {Name: middleware.CSRFCookieName, Value: csrf, Path: "/"}})
	if !bytes.Contains(staleResponseBody, []byte("UNAUTHORIZED")) {
		t.Fatalf("revoked browser session temporary-http route response=%s, want unauthorized", staleResponseBody)
	}
	auditAfterLogout, err := os.ReadFile(filepath.Join(dataRoot, "audit", temporaryOnlineAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(auditBeforeLogout, auditAfterLogout) {
		t.Fatal("revoked browser session reached temporary-network lease issuance or changed durable audit")
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

func runServeTemporaryHTTPPayload(pin string, policyEpoch uint64) map[string]any {
	return map[string]any{
		"password":           "launcher-test-password",
		"plugin_id":          "runserve-temporary-http-route",
		"plugin_version":     "1.0.0",
		"target":             netlease.Target{Host: "example.com", Port: 443, Protocol: "https"},
		"tls_fingerprint":    pin,
		"policy_epoch":       policyEpoch,
		"ttl":                int64(20 * time.Second),
		"max_bytes":          16 << 10,
		"method":             http.MethodHead,
		"path":               "/",
		"max_response_bytes": 1024,
	}
}

func runServeTemporaryHTTPBrowserCredentials(t *testing.T, loginBody []byte, jar http.CookieJar, base string) (csrf, session string) {
	t.Helper()
	var response struct {
		Data struct {
			CSRF string `json:"csrf"`
		} `json:"data"`
	}
	if err := json.Unmarshal(loginBody, &response); err != nil || response.Data.CSRF == "" {
		t.Fatalf("decode login CSRF: %v body=%s", err, loginBody)
	}
	endpoint, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range jar.Cookies(endpoint) {
		if cookie.Name == middleware.SessionCookieName {
			session = cookie.Value
		}
	}
	if session == "" {
		t.Fatal("login did not issue a browser session cookie")
	}
	return response.Data.CSRF, session
}

func runServeTemporaryHTTPRequest(t *testing.T, client *http.Client, endpoint string, payload any, csrf string, cookies []*http.Cookie) []byte {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set(middleware.CSRFHeaderName, csrf)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	responseBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if strings.HasSuffix(endpoint, "/api/system/temporary-http") && cookies == nil && response.StatusCode != http.StatusOK {
		t.Fatalf("temporary-http route status=%d body=%s", response.StatusCode, responseBody)
	}
	if strings.HasSuffix(endpoint, "/api/auth/logout") && response.StatusCode != http.StatusOK {
		t.Fatalf("logout route status=%d body=%s", response.StatusCode, responseBody)
	}
	if cookies != nil && response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale temporary-http route status=%d body=%s", response.StatusCode, responseBody)
	}
	return responseBody
}

func assertRunServeTemporaryHTTPAudit(t *testing.T, dataRoot, pin string) []byte {
	t.Helper()
	audit, err := os.ReadFile(filepath.Join(dataRoot, "audit", temporaryOnlineAuditFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte("launcher-test-password")) {
		t.Fatal("temporary-http audit exposed the administrator password")
	}
	actions := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var event netlease.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode temporary-http audit: %v", err)
		}
		if event.PluginID != "runserve-temporary-http-route" || event.TargetHost != "example.com" || event.TargetPort != 443 || event.OperatorID != "launcher-admin" || event.TLSFingerprint != pin || !event.TemporaryEgress {
			t.Fatalf("temporary-http audit identity or target mismatch: action=%q", event.Action)
		}
		if event.Action == "result" && (event.Result != "http_200" || event.Requests != 1 || event.Bytes <= 0) {
			t.Fatalf("temporary-http audit has no successful one-shot request: result=%q requests=%d bytes=%d", event.Result, event.Requests, event.Bytes)
		}
		actions[event.Action] = true
	}
	for _, action := range []string{"issued", "result", "revoked"} {
		if !actions[action] {
			t.Fatalf("temporary-http audit missing %q event", action)
		}
	}
	return audit
}
