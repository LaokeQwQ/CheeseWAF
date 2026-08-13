package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestClusterTrafficPeerReportRejectsUnknownNode(t *testing.T) {
	cfg := config.Default()
	registry := cluster.NewHeartbeatRegistry(cluster.HeartbeatRegistryOptions{})
	h := New(Options{Config: &cfg, ClusterHeartbeats: registry})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/cluster/traffic/report", strings.NewReader(`{"node_id":"unknown","report":"failure"}`))
	h.ClusterTrafficPeerReport(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code":"CLUSTER_TRAFFIC_INVALID"`) {
		t.Fatalf("unexpected error response: %s", recorder.Body.String())
	}
}

func TestClusterTrafficPeerReportAcceptsRegisteredNode(t *testing.T) {
	cfg := config.Default()
	registry := cluster.NewHeartbeatRegistry(cluster.HeartbeatRegistryOptions{})
	if _, err := registry.Record(cluster.Heartbeat{NodeID: "waf-a"}); err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &cfg, ClusterHeartbeats: registry})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/cluster/traffic/report", strings.NewReader(`{"node_id":"waf-a","report":"failure"}`))
	h.ClusterTrafficPeerReport(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
