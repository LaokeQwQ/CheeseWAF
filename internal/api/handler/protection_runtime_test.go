package handler

import (
	"errors"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestApplyProtectionRuntimeNotifiesWithAnIsolatedSnapshot(t *testing.T) {
	candidate := config.Default()
	candidate.Protection.IP.ReputationOverrides = map[string]int{"203.0.113.10": 90}
	candidate.Protection.IP.Tags = map[string][]string{"203.0.113.10": {"known-abuser"}}
	candidate.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:      "otx",
		Headers: map[string]string{"Authorization": "Bearer test"},
	}}
	var received config.ProtectionConfig
	callbackDone := make(chan struct{})
	h := New(Options{
		Config: &candidate,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			received = next
			go func(snapshot config.ProtectionConfig) {
				snapshot.IP.ReputationOverrides["203.0.113.10"] = 1
				snapshot.IP.Tags["203.0.113.10"][0] = "mutated-by-runtime"
				snapshot.IP.Providers[0].Headers["Authorization"] = "mutated-by-runtime"
				close(callbackDone)
			}(next)
			return nil
		},
	})

	if err := h.ApplyProtectionRuntime(&candidate); err != nil {
		t.Fatalf("apply protection runtime: %v", err)
	}
	<-callbackDone
	if received.IP.ReputationOverrides["203.0.113.10"] != 1 {
		t.Fatalf("callback did not receive the expected snapshot: %+v", received.IP.ReputationOverrides)
	}
	if candidate.Protection.IP.ReputationOverrides["203.0.113.10"] != 90 {
		t.Fatalf("runtime callback mutated candidate reputation: %+v", candidate.Protection.IP.ReputationOverrides)
	}
	if candidate.Protection.IP.Tags["203.0.113.10"][0] != "known-abuser" {
		t.Fatalf("runtime callback mutated candidate tags: %+v", candidate.Protection.IP.Tags)
	}
	if candidate.Protection.IP.Providers[0].Headers["Authorization"] != "Bearer test" {
		t.Fatalf("runtime callback mutated candidate provider headers: %+v", candidate.Protection.IP.Providers[0].Headers)
	}
}

func TestApplyProtectionRuntimeReturnsCallbackFailure(t *testing.T) {
	wantErr := errors.New("protection runtime unavailable")
	candidate := config.Default()
	h := New(Options{
		Config: &candidate,
		OnProtectionChanged: func(config.ProtectionConfig) error {
			return wantErr
		},
	})

	if err := h.ApplyProtectionRuntime(&candidate); !errors.Is(err, wantErr) {
		t.Fatalf("callback error = %v, want %v", err, wantErr)
	}
}

func TestApplyProtectionRuntimeRejectsInvalidCandidateBeforeCallback(t *testing.T) {
	candidate := config.Default()
	candidate.Server.Listen = ""
	called := false
	h := New(Options{
		Config: &candidate,
		OnProtectionChanged: func(config.ProtectionConfig) error {
			called = true
			return nil
		},
	})

	if err := h.ApplyProtectionRuntime(&candidate); err == nil {
		t.Fatal("expected invalid candidate to be rejected")
	}
	if called {
		t.Fatal("runtime callback called for invalid candidate")
	}
}
