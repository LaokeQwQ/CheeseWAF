package orchestrate

import (
	"strings"
	"testing"
	"time"
)

func TestBuildBootstrapPlan(t *testing.T) {
	plan, err := BuildBootstrapPlan(BootstrapRequest{
		Role:          "waf",
		NodeID:        "waf-b",
		ControllerURL: "https://controller.example:9443",
		AdvertiseAddr: "10.0.0.2:9444",
	}, "tok-1", "secret-token", time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if plan.TokenID != "tok-1" || plan.TokenValue != "secret-token" {
		t.Fatalf("token fields: %+v", plan)
	}
	if !strings.Contains(plan.JoinCommand, "cluster join") || !strings.Contains(plan.JoinCommand, "waf-b") {
		t.Fatalf("join command: %s", plan.JoinCommand)
	}
	if len(plan.RecommendedNext) == 0 {
		t.Fatal("expected recommended next steps")
	}
}

func TestBuildBootstrapPlanRejectsBadRole(t *testing.T) {
	if _, err := BuildBootstrapPlan(BootstrapRequest{
		Role: "db", NodeID: "n1", ControllerURL: "https://c", AdvertiseAddr: "1.2.3.4:1",
	}, "id", "tok", time.Now().UTC()); err == nil {
		t.Fatal("expected invalid role error")
	}
}
