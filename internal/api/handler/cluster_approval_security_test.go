package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestClusterJoinRequiresApprovalBeforeTokenConsumption(t *testing.T) {
	cfg := config.Default()
	cfg.Setup.DataDir = t.TempDir()
	cfg.Cluster.Join.RequireApproval = true
	cfg.Cluster.ClusterID = "cw-test"
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = "waf-controller"
	cfg.Cluster.Consensus.Provider = "etcd"
	cfg.Cluster.Consensus.EtcdEndpoints = []string{"https://etcd-a.internal:2379"}
	cfg.Cluster.Interconnect.Listen = "127.0.0.1:9444"
	cfg.Cluster.Interconnect.AdvertiseAddr = "127.0.0.1:9444"
	svc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &cfg, ConfigPath: filepath.Join(cfg.Setup.DataDir, "config.yaml"), ClusterIdentity: svc, ApprovalHTTP: NewApprovalHTTPHandler(ApprovalHTTPOptions{Gate: approval.NewGate(0)})})
	body := `{"token":` + strconv.Quote(token.Value) + `,"node_id":"waf-b","role":"waf","advertise_addr":"10.0.0.2:9444","csr":` + strconv.Quote(string(testNodeCSR(t, "waf-b"))) + `}`
	w := httptest.NewRecorder()
	h.ClusterJoin(w, httptest.NewRequest(http.MethodPost, "/api/cluster/join", strings.NewReader(body)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("unapproved join status=%d body=%s, want 202 pending approval", w.Code, w.Body.String())
	}
	var envelope struct {
		Data struct {
			ApprovalID string `json:"approval_id"`
			Status     string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || envelope.Data.Status != "pending" || envelope.Data.ApprovalID == "" {
		t.Fatalf("pending join response=%s", w.Body.String())
	}
	if len(svc.ListNodes()) != 0 {
		t.Fatal("unapproved join enrolled a node")
	}
	if err := svc.ValidateJoinToken(token.Value, "waf"); err != nil {
		t.Fatalf("unapproved join consumed token: %v", err)
	}
}

func TestClusterRotationRequiresPossessionOfCurrentNodeKey(t *testing.T) {
	cfg := config.Default()
	cfg.Setup.DataDir = t.TempDir()
	svc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cw-test"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.CreateJoinToken("waf", time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := svc.EnrollNodeWithCSR(token.Value, identity.NodeIdentity{NodeID: "waf-b", Role: "waf", ClusterID: "cw-test", AdvertiseAddr: "10.0.0.2:9444"}, testNodeCSR(t, "waf-b"))
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &cfg, ClusterIdentity: svc})
	body, _ := json.Marshal(map[string]string{"csr": string(testNodeCSR(t, "waf-b"))})
	r := approvalHTTPRequest(http.MethodPost, "/api/cluster/nodes/waf-b/rotate-certificate", string(body), "admin", "admin-session", "admin", "127.0.0.1:1234")
	w := httptest.NewRecorder()
	h.ClusterRotateNodeCertificate(w, withURLParam(r, "id", "waf-b"))
	if w.Code == http.StatusOK {
		t.Fatalf("administrator minted certificate without node key possession: %s", w.Body.String())
	}
	node, _ := clusterRegistrationByID(svc, "waf-b")
	if node.CertificateSerial != enrollment.Node.CertificateSerial {
		t.Fatal("unproven rotation replaced enrolled certificate")
	}
}
