package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func ptrClusterConfig(cfg config.Config) *config.Config {
	return &cfg
}

func withURLParam(req *http.Request, key, value string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
}
