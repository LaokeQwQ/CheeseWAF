package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
)

func TestClusterStatusStandalone(t *testing.T) {
	h := New(Options{Config: ptrClusterConfig(config.Default())})
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	rec := httptest.NewRecorder()
	h.ClusterStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope dto.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data: %#v", envelope.Data)
	}
	if data["mode"] != "standalone" || data["product_mode_label"] != "单机模式" {
		t.Fatalf("unexpected cluster status: %#v", data)
	}
}

func TestClusterAnsiblePackageAPI(t *testing.T) {
	h := New(Options{Config: ptrClusterConfig(config.Default())})
	body := strings.NewReader(`{"cluster_id":"cw-test","channel":"canary","password":"super-secret-value","nodes":[{"name":"waf-a","address":"10.0.0.1","role":"waf","ssh_port":22}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/deploy/ansible", body)
	rec := httptest.NewRecorder()
	h.ClusterAnsiblePackage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope dto.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data: %#v", envelope.Data)
	}
	files, ok := data["files"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected files: %#v", data["files"])
	}
	inventory, _ := files["inventory.ini"].(string)
	if !strings.Contains(inventory, "waf-a") {
		t.Fatalf("inventory missing host: %s", inventory)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("super-secret-value")) {
		t.Fatal("response must not leak secrets")
	}
}

func TestClusterDeployCheckRejectsUnsafeHost(t *testing.T) {
	h := New(Options{Config: ptrClusterConfig(config.Default())})
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/deploy/check", strings.NewReader(`{"host":"127.0.0.1;id","user":"root","password":"secret"}`))
	rec := httptest.NewRecorder()
	h.ClusterDeployCheck(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("error response must not leak password")
	}
}

func TestClusterJoinTokenAPIStoresHashAndRevokes(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "identity.json")
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		Clock:     identity.NewFakeClock(time.Unix(1000, 0)),
		ClusterID: "cw-test",
		StatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Cluster.ClusterID = "cw-test"
	h := New(Options{Config: &cfg, ClusterIdentity: identitySvc})

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join-tokens", strings.NewReader(`{"role":"waf","ttl":"15m","max_uses":1}`))
	rec := httptest.NewRecorder()
	h.ClusterCreateJoinToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data struct {
			ID    string `json:"id"`
			Value string `json:"value"`
			Hash  string `json:"hash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.ID == "" || envelope.Data.Value == "" {
		t.Fatalf("token response must include one-time id and value: %+v", envelope.Data)
	}
	if envelope.Data.Hash != "" {
		t.Fatal("API response must not expose token hash")
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(envelope.Data.Value)) {
		t.Fatal("identity state must not persist raw join token")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/cluster/join-tokens", nil)
	listRec := httptest.NewRecorder()
	h.ClusterListJoinTokens(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), `"hash"`) || strings.Contains(listRec.Body.String(), envelope.Data.Value) {
		t.Fatalf("list response must not expose token hash or value: %s", listRec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/cluster/join-tokens/"+envelope.Data.ID, nil)
	req = withURLParam(req, "id", envelope.Data.ID)
	rec = httptest.NewRecorder()
	h.ClusterRevokeJoinToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := identitySvc.ConsumeJoinToken(envelope.Data.Value); err == nil {
		t.Fatal("revoked join token must not be consumable")
	}
}

func TestClusterJoinTokenAPIDefaultServicePersistsUnderDataDir(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Setup.DataDir = dataDir
	cfg.Cluster.ClusterID = "cw-test"
	h := New(Options{Config: &cfg})

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join-tokens", strings.NewReader(`{"role":"monitor","ttl":"15m","max_uses":1}`))
	rec := httptest.NewRecorder()
	h.ClusterCreateJoinToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "cluster", "identity.json"))
	if err != nil {
		t.Fatalf("expected default identity state under data dir: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"role": "monitor"`)) {
		t.Fatalf("identity state missing created token metadata: %s", string(raw))
	}
}

func TestClusterJoinEnrollsNodeAndDoesNotLeakToken(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "cheesewaf.yaml")
	cfg := config.Default()
	cfg.Setup.DataDir = filepath.Join(root, "data")
	cfg.Storage.SQLite.Path = filepath.Join(root, "data", "cheesewaf.db")
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Cluster.NodeID = "waf-controller"
	cfg.Cluster.Interconnect.Listen = "127.0.0.1:9444"
	cfg.Cluster.Interconnect.AdvertiseAddr = "127.0.0.1:9444"
	cfg.Cluster.Nodes = []config.ClusterNodeConfig{{
		ID:            "waf-controller",
		Role:          "waf",
		AdvertiseAddr: "127.0.0.1:9444",
	}}
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatal(err)
	}
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		Clock:     identity.NewFakeClock(time.Unix(1000, 0)),
		ClusterID: "cw-test",
		StatePath: filepath.Join(cfg.Setup.DataDir, "cluster", "identity.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := identitySvc.CreateJoinToken("waf", 15*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := testNodeCSR(t, "waf-b")
	h := New(Options{Config: &cfg, ConfigPath: configPath, ClusterIdentity: identitySvc})
	body := strings.NewReader(`{"token":"` + token.Value + `","node_id":"waf-b","role":"waf","advertise_addr":"10.0.0.2:9444","listen":"0.0.0.0:9444","csr":` + strconv.Quote(string(csrPEM)) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join", body)
	rec := httptest.NewRecorder()
	h.ClusterJoin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), token.Value) {
		t.Fatal("join response must not echo raw join token")
	}
	var envelope struct {
		Data struct {
			ClusterID    string `json:"cluster_id"`
			NodeID       string `json:"node_id"`
			Certificates struct {
				CA   string `json:"ca"`
				Cert string `json:"cert"`
				Key  string `json:"key"`
			} `json:"certificates"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.ClusterID != "cw-test" || envelope.Data.NodeID != "waf-b" {
		t.Fatalf("unexpected join response: %+v", envelope.Data)
	}
	if envelope.Data.Certificates.CA == "" || envelope.Data.Certificates.Cert == "" {
		t.Fatal("join response must include CA and certificate material")
	}
	if envelope.Data.Certificates.Key != "" {
		t.Fatal("join response must not include node private key; the node generates it locally")
	}
	if err := identitySvc.ConsumeJoinToken(token.Value); err == nil {
		t.Fatal("join token must be consumed by enrollment")
	}
	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, node := range reloaded.Cluster.Nodes {
		if node.ID == "waf-b" && node.AdvertiseAddr == "10.0.0.2:9444" {
			found = true
		}
	}
	if !found {
		t.Fatalf("joined node was not persisted to controller config: %+v", reloaded.Cluster.Nodes)
	}
}

func TestClusterJoinRejectedDoesNotExposeTokenState(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Setup.DataDir = filepath.Join(root, "data")
	cfg.Storage.SQLite.Path = filepath.Join(root, "data", "cheesewaf.db")
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Cluster.NodeID = "waf-controller"
	cfg.Cluster.Interconnect.Listen = "127.0.0.1:9444"
	cfg.Cluster.Interconnect.AdvertiseAddr = "127.0.0.1:9444"
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		Clock:     identity.NewFakeClock(time.Unix(1000, 0)),
		ClusterID: "cw-test",
		StatePath: filepath.Join(cfg.Setup.DataDir, "cluster", "identity.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := identitySvc.CreateJoinToken("monitor", 15*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := testNodeCSR(t, "waf-b")
	h := New(Options{Config: &cfg, ConfigPath: filepath.Join(root, "cheesewaf.yaml"), ClusterIdentity: identitySvc})
	body := strings.NewReader(`{"token":"` + token.Value + `","node_id":"waf-b","role":"waf","advertise_addr":"10.0.0.2:9444","csr":` + strconv.Quote(string(csrPEM)) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join", body)
	rec := httptest.NewRecorder()
	h.ClusterJoin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	bodyText := rec.Body.String()
	for _, leaked := range []string{"monitor", "waf", "role", "expired", "revoked", "already used", "not found"} {
		if strings.Contains(bodyText, leaked) {
			t.Fatalf("join rejection leaked token state %q in body: %s", leaked, bodyText)
		}
	}
	if !strings.Contains(bodyText, "invalid join token or join request") {
		t.Fatalf("expected generic rejection message, got %s", bodyText)
	}
}

func TestClusterJoinRejectsDuplicateNodeBeforeConsumingToken(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "cheesewaf.yaml")
	cfg := config.Default()
	cfg.Setup.DataDir = filepath.Join(root, "data")
	cfg.Storage.SQLite.Path = filepath.Join(root, "data", "cheesewaf.db")
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Cluster.NodeID = "waf-controller"
	cfg.Cluster.Interconnect.Listen = "127.0.0.1:9444"
	cfg.Cluster.Interconnect.AdvertiseAddr = "127.0.0.1:9444"
	cfg.Cluster.Nodes = []config.ClusterNodeConfig{{
		ID:            "waf-b",
		Role:          "waf",
		AdvertiseAddr: "10.0.0.2:9444",
	}}
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatal(err)
	}
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		Clock:     identity.NewFakeClock(time.Unix(1000, 0)),
		ClusterID: "cw-test",
		StatePath: filepath.Join(cfg.Setup.DataDir, "cluster", "identity.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := identitySvc.CreateJoinToken("waf", 15*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := testNodeCSR(t, "waf-b")
	h := New(Options{Config: &cfg, ConfigPath: configPath, ClusterIdentity: identitySvc})
	body := strings.NewReader(`{"token":"` + token.Value + `","node_id":"waf-b","role":"waf","advertise_addr":"10.0.0.2:9444","csr":` + strconv.Quote(string(csrPEM)) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join", body)
	rec := httptest.NewRecorder()
	h.ClusterJoin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := identitySvc.ConsumeJoinToken(token.Value); err != nil {
		t.Fatalf("duplicate node preflight must not consume token: %v", err)
	}
}

func TestClusterJoinRollsBackEnrollmentWhenConfigSaveFails(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config-is-directory")
	if err := os.Mkdir(configPath, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Setup.DataDir = filepath.Join(root, "data")
	cfg.Storage.SQLite.Path = filepath.Join(root, "data", "cheesewaf.db")
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Cluster.NodeID = "waf-controller"
	cfg.Cluster.Interconnect.Listen = "127.0.0.1:9444"
	cfg.Cluster.Interconnect.AdvertiseAddr = "127.0.0.1:9444"
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		Clock:     identity.NewFakeClock(time.Unix(1000, 0)),
		ClusterID: "cw-test",
		StatePath: filepath.Join(cfg.Setup.DataDir, "cluster", "identity.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := identitySvc.CreateJoinToken("waf", 15*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := testNodeCSR(t, "waf-b")
	h := New(Options{Config: &cfg, ConfigPath: configPath, ClusterIdentity: identitySvc})
	body := strings.NewReader(`{"token":"` + token.Value + `","node_id":"waf-b","role":"waf","advertise_addr":"10.0.0.2:9444","csr":` + strconv.Quote(string(csrPEM)) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join", body)
	rec := httptest.NewRecorder()
	h.ClusterJoin(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if nodes := identitySvc.ListNodes(); len(nodes) != 0 {
		t.Fatalf("failed join must roll back node registration: %+v", nodes)
	}
	if err := identitySvc.ConsumeJoinToken(token.Value); err != nil {
		t.Fatalf("failed join must roll back token usage: %v", err)
	}
}

func ptrClusterConfig(cfg config.Config) *config.Config {
	return &cfg
}

func testNodeCSR(t *testing.T, nodeID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{nodeID},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})
}

func withURLParam(req *http.Request, key, value string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
}
