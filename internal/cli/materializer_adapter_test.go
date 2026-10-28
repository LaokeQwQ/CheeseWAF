package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/materializer"
)

func TestNewProtectionPolicyMaterializerRequiresRuntimeCallback(t *testing.T) {
	cfg := config.Default()
	h := handler.New(handler.Options{Config: &cfg, ConfigPath: filepath.Join(t.TempDir(), "config.yaml")})

	_, err := NewProtectionPolicyMaterializer(h, nil, t.TempDir())
	if !errors.Is(err, ErrMaterializerRuntimeRequired) {
		t.Fatalf("error = %v, want %v", err, ErrMaterializerRuntimeRequired)
	}
}

func TestNewProtectionPolicyMaterializerAppliesExactCommitAndRetriesIdempotently(t *testing.T) {
	runtimeDir := t.TempDir()
	configPath := filepath.Join(runtimeDir, "config", "cheesewaf.yaml")
	cfg := config.Default()
	cfg.Setup.RuntimeDir = runtimeDir
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://local-user:local-password@example.invalid/management"
	cfg.TLS.CertFile = "/etc/cheesewaf/node-cert.pem"
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatalf("new state machine: %v", err)
	}
	if _, err := machine.InstallLeadership(1, "leader-a"); err != nil {
		t.Fatalf("install leadership: %v", err)
	}
	policy := config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelHigh,
		APISecurity: config.ProtectionLevelStrict,
		BotCC:       config.ProtectionLevelLow,
		ThreatIntel: config.ProtectionLevelSmart,
	}
	payload, digest, err := desiredstate.EncodeProtectionPolicy(policy)
	if err != nil {
		t.Fatalf("encode desired state: %v", err)
	}
	commit, err := machine.Propose(controlplane.Proposal{
		LeaderID: "leader-a", ExpectedEpoch: 1, Version: desiredstate.Version,
		Payload: payload, Digest: digest, Nonce: "nonce-1",
	})
	if err != nil {
		t.Fatalf("propose desired state: %v", err)
	}
	if err := machine.LoadSnapshot(commit.State); err != nil {
		t.Fatalf("install committed snapshot: %v", err)
	}

	var runtimeCalls atomic.Int32
	h := handler.New(handler.Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			runtimeCalls.Add(1)
			if next.Policy != policy {
				t.Fatalf("runtime policy = %+v, want %+v", next.Policy, policy)
			}
			return nil
		},
	})
	applier, err := NewProtectionPolicyMaterializer(h, machine, runtimeDir)
	if err != nil {
		t.Fatalf("new materializer adapter: %v", err)
	}
	if err := applier.ApplyCommitted(context.Background(), commit); err != nil {
		t.Fatalf("apply committed policy: %v", err)
	}
	if got := runtimeCalls.Load(); got != 1 {
		t.Fatalf("runtime callback count after first apply = %d, want 1", got)
	}

	persisted, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if persisted.Protection.Policy != policy {
		t.Fatalf("persisted policy = %+v, want %+v", persisted.Protection.Policy, policy)
	}
	if h.Config.Protection.Policy == policy {
		t.Fatal("handler in-memory config was published by the persistence-only adapter")
	}

	journal, err := materializer.NewJournalStore(filepath.Join(runtimeDir, "materializer"), materializer.Hooks{})
	if err != nil {
		t.Fatalf("reopen materializer journal: %v", err)
	}
	receipt, err := journal.LoadJournal()
	if err != nil {
		t.Fatalf("load materializer journal: %v", err)
	}
	if receipt.Phase != materializer.PhaseApplied {
		t.Fatalf("journal phase = %s, want %s", receipt.Phase, materializer.PhaseApplied)
	}
	raw, err := os.ReadFile(filepath.Join(runtimeDir, "materializer", "journal.json"))
	if err != nil {
		t.Fatalf("read materializer journal: %v", err)
	}
	for _, forbidden := range []string{"local-password", "/etc/cheesewaf/node-cert.pem"} {
		if string(raw) == "" || containsString(string(raw), forbidden) {
			t.Fatalf("journal contains node-local secret/path %q: %s", forbidden, raw)
		}
	}

	if err := applier.ApplyCommitted(context.Background(), commit); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if got := runtimeCalls.Load(); got != 1 {
		t.Fatalf("runtime callback count after exact retry = %d, want 1", got)
	}
}

func containsString(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
