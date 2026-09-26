package migration

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"gopkg.in/yaml.v3"
)

func TestProductionHandoffRoundTripAndConfigBinding(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Storage.Profile = config.StorageProfileProduction
	cfg.Cluster.ClusterID = "cluster-handoff"
	private, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("encode candidate: %v", err)
	}
	digest := digestBytes(private)
	now := time.Date(2026, 9, 21, 1, 2, 3, 0, time.UTC)
	handoff := ProductionHandoff{
		Version: productionHandoffVersion, SnapshotID: "snapshot-handoff",
		TemporaryConfigDigest: digestBytes([]byte("temporary")), ProductionConfigDigest: digest,
		CandidateDigest: digest, InitialStateHash: digestBytes([]byte("initial")),
		TokenMetadataDigest: digestBytes([]byte("tokens")), ClusterID: cfg.Cluster.ClusterID,
		Actor: "admin-handoff", CommittedAt: now,
		SessionsInvalidated: true, SetupInvalidated: true, JoinInvalidated: true,
		CAPTCHAInvalidated: true, LocksInvalidated: true,
	}
	if err := writeProductionHandoff(dataDir, handoff); err != nil {
		t.Fatalf("write handoff: %v", err)
	}
	got, err := ValidateProductionHandoff(dataDir, &cfg)
	if err != nil {
		t.Fatalf("validate handoff: %v", err)
	}
	if got.SnapshotID != handoff.SnapshotID || got.Evidence().TokenMetadataDigest != handoff.TokenMetadataDigest {
		t.Fatalf("handoff changed on round trip: got=%+v want=%+v", got, handoff)
	}
	path := filepath.Join(dataDir, "migration", productionHandoffFileName)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("handoff permissions: info=%v err=%v", info, err)
	}
}

func TestProductionHandoffRejectsStaleConfigAndIncompleteInvalidation(t *testing.T) {
	dataDir := t.TempDir()
	handoff := ProductionHandoff{
		Version: productionHandoffVersion, SnapshotID: "snapshot-stale",
		TemporaryConfigDigest: digestBytes([]byte("temporary")), ProductionConfigDigest: digestBytes([]byte("production")),
		CandidateDigest: digestBytes([]byte("production")), InitialStateHash: digestBytes([]byte("initial")),
		TokenMetadataDigest: digestBytes([]byte("tokens")), ClusterID: "cluster-stale", Actor: "admin-stale",
		CommittedAt: time.Now().UTC(), SessionsInvalidated: true,
	}
	if err := writeProductionHandoff(dataDir, handoff); !errors.Is(err, ErrProductionHandoff) {
		t.Fatalf("incomplete handoff write error=%v, want ErrProductionHandoff", err)
	}
}
