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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/deploy"
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

func TestClusterDeployTaskRunCreatesTrackableTaskAndRedactsSecrets(t *testing.T) {
	secret := "super-secret-value"
	runner := &fakeClusterDeployRunner{
		deployResult: deploy.DeployResult{
			OK:              true,
			Host:            "node-a.example.com",
			StartedAt:       time.Unix(1000, 0).UTC(),
			FinishedAt:      time.Unix(1001, 0).UTC(),
			Output:          "installed with " + secret,
			OutputTruncated: false,
		},
	}
	h := New(Options{
		Config: ptrClusterConfig(config.Default()),
		ClusterDeployTasks: deploy.NewTaskManager(deploy.TaskManagerOptions{
			Runner: runner,
			NewID:  func() string { return "deploy-task-1" },
		}),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/deploy/tasks", strings.NewReader(`{"host":"node-a.example.com","user":"root","password":"`+secret+`","action":"install"}`))
	rec := httptest.NewRecorder()
	h.ClusterStartDeployTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("create task response leaked secret: %s", rec.Body.String())
	}

	var created struct {
		Data deploy.Task `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.ID != "deploy-task-1" {
		t.Fatalf("task id=%q, want deploy-task-1", created.Data.ID)
	}
	task := waitClusterDeployTask(t, h, created.Data.ID, deploy.TaskStatusSucceeded)
	if task.Output != "installed with <redacted>" {
		t.Fatalf("task output was not redacted: %q", task.Output)
	}

	getReq := withURLParam(httptest.NewRequest(http.MethodGet, "/api/cluster/deploy/tasks/"+created.Data.ID, nil), "id", created.Data.ID)
	getRec := httptest.NewRecorder()
	h.ClusterGetDeployTask(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), secret) {
		t.Fatalf("task lookup leaked secret: %s", getRec.Body.String())
	}
}

func TestClusterDeployTaskFailureDoesNotLeakPrivateKey(t *testing.T) {
	privateKey := testECDSAPrivateKeyPEM(t)
	runner := &fakeClusterDeployRunner{deployErr: errors.New("private key failed: " + privateKey)}
	h := New(Options{
		Config: ptrClusterConfig(config.Default()),
		ClusterDeployTasks: deploy.NewTaskManager(deploy.TaskManagerOptions{
			Runner: runner,
			NewID:  func() string { return "deploy-task-2" },
		}),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/deploy/tasks", strings.NewReader(`{"host":"node-b.example.com","user":"root","private_key":`+strconv.Quote(privateKey)+`,"action":"restart-service"}`))
	rec := httptest.NewRecorder()
	h.ClusterStartDeployTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	task := waitClusterDeployTask(t, h, "deploy-task-2", deploy.TaskStatusFailed)
	if strings.Contains(task.Error, privateKey) || strings.Contains(task.Output, privateKey) {
		t.Fatalf("task failure leaked private key: %+v", task)
	}
	if !strings.Contains(task.Error, "<redacted>") {
		t.Fatalf("task error should retain useful redaction marker: %q", task.Error)
	}
}

func TestClusterAuditCombinesHTTPAuditAndDeployTaskEvents(t *testing.T) {
	auditor := middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))
	httpAt := time.Unix(2000, 0).UTC()
	if err := auditor.Write(context.Background(), middleware.AuditEntry{
		Timestamp: httpAt,
		Subject:   "admin-id",
		User:      "admin",
		Role:      "admin",
		Method:    http.MethodPost,
		Path:      "/api/cluster/join-tokens",
		Status:    http.StatusOK,
		RemoteIP:  "192.0.2.10:53412",
		LatencyMS: 12,
		Target:    "join-token",
		Message:   "join token created",
	}); err != nil {
		t.Fatal(err)
	}
	if err := auditor.Write(context.Background(), middleware.AuditEntry{
		Timestamp: httpAt.Add(time.Second),
		User:      "admin",
		Method:    http.MethodGet,
		Path:      "/api/system",
		Status:    http.StatusOK,
	}); err != nil {
		t.Fatal(err)
	}
	if err := auditor.Write(context.Background(), middleware.AuditEntry{
		Timestamp: httpAt.Add(2 * time.Second),
		User:      "admin",
		Method:    http.MethodGet,
		Path:      "/api/cluster/audit",
		Status:    http.StatusOK,
	}); err != nil {
		t.Fatal(err)
	}

	clockValues := []time.Time{
		time.Unix(2001, 0).UTC(),
		time.Unix(2002, 0).UTC(),
		time.Unix(2003, 0).UTC(),
		time.Unix(2004, 0).UTC(),
		time.Unix(2005, 0).UTC(),
	}
	clockIndex := 0
	runner := &fakeClusterDeployRunner{
		checkResult: deploy.CheckResult{
			OK:      true,
			Host:    "node-a.example.com",
			User:    "root",
			Port:    22,
			Message: "checked",
		},
	}
	h := New(Options{
		Config:  ptrClusterConfig(config.Default()),
		Auditor: auditor,
		ClusterDeployTasks: deploy.NewTaskManager(deploy.TaskManagerOptions{
			Runner: runner,
			NewID:  func() string { return "deploy-task-audit" },
			Now: func() time.Time {
				if clockIndex >= len(clockValues) {
					return clockValues[len(clockValues)-1]
				}
				value := clockValues[clockIndex]
				clockIndex++
				return value
			},
		}),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/deploy/tasks", strings.NewReader(`{"host":"node-a.example.com","user":"root","action":"check"}`))
	rec := httptest.NewRecorder()
	h.ClusterStartDeployTask(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	_ = waitClusterDeployTask(t, h, "deploy-task-audit", deploy.TaskStatusSucceeded)

	rec = httptest.NewRecorder()
	h.ClusterAudit(rec, httptest.NewRequest(http.MethodGet, "/api/cluster/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data struct {
			Items []clusterAuditEntry `json:"items"`
			Total int                 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Total < 2 {
		t.Fatalf("expected combined audit entries, got %+v", envelope.Data.Items)
	}
	foundHTTP := false
	foundTask := false
	for _, item := range envelope.Data.Items {
		if item.Path == "/api/system" {
			t.Fatalf("non-cluster audit entry leaked into cluster audit: %+v", item)
		}
		if item.Path == "/api/cluster/audit" {
			t.Fatalf("cluster audit polling entry must not pollute audit view: %+v", item)
		}
		if item.Source == "management_api" && item.Action == "create_join_token" && item.Actor == "admin" && item.Message == "join token created" {
			foundHTTP = true
		}
		if item.Source == "deploy_task" && item.TaskID == "deploy-task-audit" && item.Target == "node-a.example.com" {
			foundTask = true
		}
	}
	if !foundHTTP || !foundTask {
		t.Fatalf("missing expected audit sources: http=%v task=%v items=%+v", foundHTTP, foundTask, envelope.Data.Items)
	}
}

func TestClusterJoinWritesSafeAuditEntry(t *testing.T) {
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
	auditor := middleware.NewAuditor(filepath.Join(root, "audit.jsonl"))
	h := New(Options{Config: &cfg, ConfigPath: filepath.Join(root, "cheesewaf.yaml"), ClusterIdentity: identitySvc, Auditor: auditor})
	body := strings.NewReader(`{"token":"` + token.Value + `","node_id":"waf-b","role":"waf","advertise_addr":"10.0.0.2:9444","csr":` + strconv.Quote(string(csrPEM)) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/join", body)
	req.RemoteAddr = "198.51.100.7:52122"
	rec := httptest.NewRecorder()
	h.ClusterJoin(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	auditText := string(raw)
	for _, leaked := range []string{token.Value, string(csrPEM), "PRIVATE KEY"} {
		if strings.Contains(auditText, leaked) {
			t.Fatalf("cluster join audit leaked sensitive material %q in %s", leaked, auditText)
		}
	}
	entries, err := h.clusterAuditEntries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one join audit entry, got %+v", entries)
	}
	entry := entries[0]
	if entry.Source != "cluster_join" || entry.Action != "join_cluster" || entry.Status != "failed" || entry.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected join audit entry: %+v", entry)
	}
	if entry.Actor != "join-token" || entry.Target != "node:waf-b" || entry.RemoteIP != "198.51.100.7" {
		t.Fatalf("join audit should expose safe actor/target/remote ip: %+v", entry)
	}
	if strings.Contains(entry.Message, token.Value) || strings.Contains(entry.Message, "monitor") {
		t.Fatalf("join audit message leaked token state: %+v", entry)
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

func TestClusterRotateNodeCertificateWithCSRDoesNotReturnPrivateKey(t *testing.T) {
	clock := identity.NewFakeClock(time.Unix(1000, 0))
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		Clock:     clock,
		ClusterID: "cw-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := identitySvc.CreateJoinToken("waf", 15*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentCSR := testNodeCSR(t, "waf-b")
	enrollment, err := identitySvc.EnrollNodeWithCSR(token.Value, identity.NodeIdentity{
		NodeID:        "waf-b",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.2:9444",
	}, enrollmentCSR)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * 24 * time.Hour)
	h := New(Options{Config: ptrClusterConfig(config.Default()), ClusterIdentity: identitySvc})
	rotationCSR := testNodeCSR(t, "waf-b")
	req := withURLParam(
		httptest.NewRequest(http.MethodPost, "/api/cluster/nodes/waf-b/rotate-certificate", strings.NewReader(`{"csr":`+strconv.Quote(string(rotationCSR))+`}`)),
		"id",
		"waf-b",
	)
	rec := httptest.NewRecorder()
	h.ClusterRotateNodeCertificate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var envelope struct {
		Data struct {
			Node         identity.NodeRegistration `json:"node"`
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
	if envelope.Data.Node.NodeID != "waf-b" {
		t.Fatalf("unexpected node response: %+v", envelope.Data.Node)
	}
	if envelope.Data.Node.CertificateSerial == "" || envelope.Data.Node.CertificateSerial == enrollment.Node.CertificateSerial {
		t.Fatalf("rotation must update certificate serial: old=%s new=%s", enrollment.Node.CertificateSerial, envelope.Data.Node.CertificateSerial)
	}
	if envelope.Data.Certificates.CA == "" || envelope.Data.Certificates.Cert == "" {
		t.Fatal("rotation response must include CA and node certificate")
	}
	if envelope.Data.Certificates.Key != "" || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("rotation response must not expose or mint a node private key")
	}
}

func TestClusterRotateNodeCertificateRejectsRevokedNode(t *testing.T) {
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := identitySvc.CreateJoinToken("waf", 15*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	csr := testNodeCSR(t, "waf-b")
	if _, err := identitySvc.EnrollNodeWithCSR(token.Value, identity.NodeIdentity{
		NodeID:        "waf-b",
		Role:          "waf",
		ClusterID:     "cw-test",
		AdvertiseAddr: "10.0.0.2:9444",
	}, csr); err != nil {
		t.Fatal(err)
	}
	if err := identitySvc.RevokeNode("waf-b", "compromised"); err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: ptrClusterConfig(config.Default()), ClusterIdentity: identitySvc})
	req := withURLParam(
		httptest.NewRequest(http.MethodPost, "/api/cluster/nodes/waf-b/rotate-certificate", strings.NewReader(`{"csr":`+strconv.Quote(string(testNodeCSR(t, "waf-b")))+`}`)),
		"id",
		"waf-b",
	)
	rec := httptest.NewRecorder()
	h.ClusterRotateNodeCertificate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("rotation rejection must not leak key material")
	}
}

type fakeClusterDeployRunner struct {
	checkResult  deploy.CheckResult
	checkErr     error
	deployResult deploy.DeployResult
	deployErr    error
}

func (r *fakeClusterDeployRunner) Check(_ context.Context, req deploy.SSHDeploymentRequest) (deploy.CheckResult, error) {
	result := r.checkResult
	if result.Host == "" {
		result.Host = strings.TrimSpace(req.Host)
	}
	if result.User == "" {
		result.User = strings.TrimSpace(req.User)
	}
	if result.Port == 0 {
		result.Port = req.Port
	}
	return result, r.checkErr
}

func (r *fakeClusterDeployRunner) Deploy(_ context.Context, req deploy.SSHDeploymentRequest) (deploy.DeployResult, error) {
	result := r.deployResult
	if result.Host == "" {
		result.Host = strings.TrimSpace(req.Host)
	}
	return result, r.deployErr
}

func waitClusterDeployTask(t *testing.T, h *Handler, id string, want string) deploy.Task {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/cluster/deploy/tasks/"+id, nil), "id", id)
		rec := httptest.NewRecorder()
		h.ClusterGetDeployTask(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var envelope struct {
			Data deploy.Task `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Data.Status == want {
			return envelope.Data
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach status %s", id, want)
	return deploy.Task{}
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

func testECDSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}))
}

func withURLParam(req *http.Request, key, value string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
}
