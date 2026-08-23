package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestClusterBootstrapPlanReturnsJoinCommand(t *testing.T) {
	cfg := config.Default()
	cfg.Cluster.Enabled = true
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.ClusterID = "mesh-1"
	cfg.Cluster.NodeID = "waf-a"
	cfg.Cluster.HAMode = "single-node"
	cfg.Cluster.Consensus.Provider = "etcd"
	cfg.Cluster.Consensus.EtcdEndpoints = []string{"https://etcd-a.internal:2379"}
	cfg.Cluster.Nodes = []config.ClusterNodeConfig{
		{ID: "waf-a", Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
	}
	cfg.APISec.Audit.Enabled = false
	identitySvc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "mesh-1"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		Config:          &cfg,
		ClusterIdentity: identitySvc,
		now:             func() time.Time { return time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC) },
	}
	body, _ := json.Marshal(map[string]any{
		"role":           "waf",
		"node_id":        "waf-b",
		"controller_url": "https://controller.example:9443",
		"advertise_addr": "10.0.0.2:9444",
		"token_ttl":      "15m",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/orchestrate/bootstrap", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{
		Subject: "admin", Username: "admin", Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.ClusterBootstrapPlan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data struct {
			JoinCommand string `json:"join_command"`
			TokenValue  string `json:"token_value"`
			NodeID      string `json:"node_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.NodeID != "waf-b" || envelope.Data.TokenValue == "" {
		t.Fatalf("unexpected plan: %+v", envelope.Data)
	}
	if !bytes.Contains([]byte(envelope.Data.JoinCommand), []byte("cluster join")) {
		t.Fatalf("join command missing: %s", envelope.Data.JoinCommand)
	}
}

func TestClusterConsensusCoordinatorRefreshesConfiguredProvider(t *testing.T) {
	cfg := config.Default()
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = "waf-a"
	h := &Handler{Config: &cfg}
	status := cluster.Status{Mode: "single-node", MajorityConfirmed: true, CanWriteConfig: true}
	if got := h.clusterConsensusCoordinator().Evaluate(status, nil).Provider; got != "builtin" {
		t.Fatalf("initial provider=%q, want builtin", got)
	}

	cfg.Cluster.Consensus.Provider = "etcd"
	cfg.Cluster.Consensus.EtcdEndpoints = []string{"https://etcd-a.internal:2379"}
	snap := h.clusterConsensusCoordinator().Evaluate(status, nil)
	if snap.Provider != "etcd" || !snap.EtcdConfigured || snap.CanWriteConfig {
		t.Fatalf("coordinator did not refresh to fail-closed etcd selection: %+v", snap)
	}
}
