package handler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestConfigSnapshotReturnsAnIsolatedCopy(t *testing.T) {
	candidate := config.Default()
	candidate.Protection.IP.ReputationOverrides = map[string]int{"203.0.113.10": 90}
	h := New(Options{Config: &candidate})

	snapshot, err := h.ConfigSnapshot(context.Background())
	if err != nil {
		t.Fatalf("config snapshot: %v", err)
	}
	snapshot.Protection.IP.ReputationOverrides["203.0.113.10"] = 1
	if got := h.currentConfig().Protection.IP.ReputationOverrides["203.0.113.10"]; got != 90 {
		t.Fatalf("snapshot mutation changed handler config: got %d, want 90", got)
	}
}

func TestPersistMaterializedConfigWritesOnlyTheCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cheesewaf.yaml")
	candidate := config.Default()
	candidate.Protection.Bot.Secret = config.BotSecretPlaceholder
	if err := config.Save(path, &candidate); err != nil {
		t.Fatalf("save initial config: %v", err)
	}
	h := New(Options{Config: &candidate, ConfigPath: path})
	next, err := config.Clone(&candidate)
	if err != nil {
		t.Fatal(err)
	}
	next.Protection.Policy.WebAttack = config.ProtectionLevelStrict
	if err := h.PersistMaterializedConfig(context.Background(), next); err != nil {
		t.Fatalf("persist materialized config: %v", err)
	}
	persisted, err := config.Load(path)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if persisted.Protection.Policy.WebAttack != config.ProtectionLevelStrict {
		t.Fatalf("persisted policy = %q, want strict", persisted.Protection.Policy.WebAttack)
	}
	if config.IsWeakBotSecret(persisted.Protection.Bot.Secret) {
		t.Fatalf("persisted config retained a weak bot secret: %q", persisted.Protection.Bot.Secret)
	}
	if candidate.Protection.Bot.Secret != config.BotSecretPlaceholder {
		t.Fatalf("persistence adapter mutated caller bot secret: %q", candidate.Protection.Bot.Secret)
	}
	if h.currentConfig().Protection.Policy.WebAttack == config.ProtectionLevelStrict {
		t.Fatal("persistence adapter published the candidate before runtime commit")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "versions"))
	if err != nil {
		t.Fatalf("read config versions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("config version count = %d, want 1", len(entries))
	}
	versionBytes, err := os.ReadFile(filepath.Join(dir, "versions", entries[0].Name()))
	if err != nil {
		t.Fatalf("read config version: %v", err)
	}
	if strings.Contains(string(versionBytes), config.BotSecretPlaceholder) {
		t.Fatal("config version retained the bot secret placeholder")
	}
	next.Protection.Policy.WebAttack = config.ProtectionLevelLow
	if persisted.Protection.Policy.WebAttack == config.ProtectionLevelLow {
		t.Fatal("persistence adapter retained an alias to the caller candidate")
	}
}

func TestPersistMaterializedConfigRequiresDurablePath(t *testing.T) {
	candidate := config.Default()
	h := New(Options{Config: &candidate})
	if err := h.PersistMaterializedConfig(context.Background(), &candidate); !errors.Is(err, ErrMaterializedConfigPath) {
		t.Fatalf("persist without config path error = %v, want ErrMaterializedConfigPath", err)
	}
}

func TestPersistMaterializedConfigHonorsCancellationAndFreeze(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cheesewaf.yaml")
	candidate := config.Default()
	if err := config.Save(path, &candidate); err != nil {
		t.Fatalf("save initial config: %v", err)
	}
	h := New(Options{Config: &candidate, ConfigPath: path})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	next, err := config.Clone(&candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.PersistMaterializedConfig(canceled, next); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled persist error = %v, want context.Canceled", err)
	}
	h.configWriteFrozen = true
	h.configFreezeReason = "test freeze"
	if err := h.PersistMaterializedConfig(context.Background(), next); err == nil || !strings.Contains(err.Error(), "test freeze") {
		t.Fatalf("frozen persist error = %v, want freeze reason", err)
	}
}

func TestPersistMaterializedConfigRestoresFileWhenVersionWriteFails(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cheesewaf.yaml")
	candidate := config.Default()
	candidate.Setup.RuntimeDir = runtimeDir
	if err := config.Save(path, &candidate); err != nil {
		t.Fatalf("save initial config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "versions"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "versions"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &candidate, ConfigPath: path})
	next, err := config.Clone(&candidate)
	if err != nil {
		t.Fatal(err)
	}
	next.Protection.Policy.WebAttack = config.ProtectionLevelStrict
	if err := h.PersistMaterializedConfig(context.Background(), next); err == nil {
		t.Fatal("version write failure was reported as success")
	}
	restored, err := config.Load(path)
	if err != nil {
		t.Fatalf("load restored config: %v", err)
	}
	if restored.Protection.Policy.WebAttack != candidate.Protection.Policy.WebAttack {
		t.Fatalf("config was not restored after version failure: got %q, want %q", restored.Protection.Policy.WebAttack, candidate.Protection.Policy.WebAttack)
	}
}
