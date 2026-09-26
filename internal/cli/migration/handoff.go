package migration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"gopkg.in/yaml.v3"
)

const (
	productionHandoffVersion  = 1
	productionHandoffFileName = "production-handoff.json"
	productionHandoffMaxBytes = 32 << 10
)

var ErrProductionHandoff = errors.New("production migration handoff is invalid")

// ProductionHandoff is metadata-only proof that the migration transaction
// committed and invalidated every temporary security artifact. It never
// contains credentials, DSNs, management snapshots, or token contents.
type ProductionHandoff struct {
	Version                int       `json:"version"`
	SnapshotID             string    `json:"snapshot_id"`
	TemporaryConfigDigest  string    `json:"temporary_config_digest"`
	ProductionConfigDigest string    `json:"production_config_digest"`
	CandidateDigest        string    `json:"candidate_digest"`
	InitialStateHash       string    `json:"initial_state_hash"`
	TokenMetadataDigest    string    `json:"token_metadata_digest"`
	ClusterID              string    `json:"cluster_id"`
	Actor                  string    `json:"actor"`
	CommittedAt            time.Time `json:"committed_at"`
	SessionsInvalidated    bool      `json:"sessions_invalidated"`
	SetupInvalidated       bool      `json:"setup_invalidated"`
	JoinInvalidated        bool      `json:"join_invalidated"`
	CAPTCHAInvalidated     bool      `json:"captcha_invalidated"`
	LocksInvalidated       bool      `json:"locks_invalidated"`
}

func (h ProductionHandoff) Complete() bool {
	return h.SessionsInvalidated && h.SetupInvalidated && h.JoinInvalidated && h.CAPTCHAInvalidated && h.LocksInvalidated
}

// Evidence converts the file proof into the storage-owned verification
// contract without exposing any private migration payload.
func (h ProductionHandoff) Evidence() storage.MigrationHandoffEvidence {
	return storage.MigrationHandoffEvidence{
		SnapshotID: h.SnapshotID, TemporaryConfigDigest: h.TemporaryConfigDigest,
		ProductionConfigDigest: h.ProductionConfigDigest, CandidateDigest: h.CandidateDigest,
		InitialStateHash: h.InitialStateHash, TokenMetadataDigest: h.TokenMetadataDigest,
		ClusterID: h.ClusterID, Actor: h.Actor, CommittedAt: h.CommittedAt,
		SessionsInvalidated: h.SessionsInvalidated, SetupInvalidated: h.SetupInvalidated,
		JoinInvalidated: h.JoinInvalidated, CAPTCHAInvalidated: h.CAPTCHAInvalidated,
		LocksInvalidated: h.LocksInvalidated,
	}
}

func productionHandoffPath(dataDir string) (string, error) {
	if dataDir == "" {
		return "", ErrProductionHandoff
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", ErrProductionHandoff
	}
	return filepath.Join(filepath.Clean(abs), "migration", productionHandoffFileName), nil
}

func writeProductionHandoff(dataDir string, handoff ProductionHandoff) error {
	if err := validateProductionHandoff(handoff); err != nil {
		return err
	}
	path, err := productionHandoffPath(dataDir)
	if err != nil {
		return err
	}
	if err := secureRecoveryDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	raw, err := json.Marshal(handoff)
	if err != nil || len(raw)+1 > productionHandoffMaxBytes {
		return ErrProductionHandoff
	}
	raw = append(raw, '\n')
	return writePrivateFileAtomic(path, raw, 0o600)
}

// ReadProductionHandoff returns the owner-only runtime handoff. Missing or
// malformed evidence is distinct from a pending cutover and must fail closed.
func ReadProductionHandoff(dataDir string) (ProductionHandoff, error) {
	path, err := productionHandoffPath(dataDir)
	if err != nil {
		return ProductionHandoff{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ProductionHandoff{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > productionHandoffMaxBytes {
		return ProductionHandoff{}, ErrProductionHandoff
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > productionHandoffMaxBytes {
		return ProductionHandoff{}, ErrProductionHandoff
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var handoff ProductionHandoff
	if err := decoder.Decode(&handoff); err != nil {
		return ProductionHandoff{}, ErrProductionHandoff
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ProductionHandoff{}, ErrProductionHandoff
	}
	if err := validateProductionHandoff(handoff); err != nil {
		return ProductionHandoff{}, err
	}
	return handoff, nil
}

func validateProductionHandoff(h ProductionHandoff) error {
	if h.Version != productionHandoffVersion || approval.ValidateIdentifier(h.SnapshotID) != nil || approval.ValidateIdentifier(h.ClusterID) != nil || approval.ValidateIdentifier(h.Actor) != nil || h.CommittedAt.IsZero() || !h.Complete() {
		return ErrProductionHandoff
	}
	for _, digest := range []string{h.TemporaryConfigDigest, h.ProductionConfigDigest, h.CandidateDigest, h.InitialStateHash, h.TokenMetadataDigest} {
		if len(digest) != 64 {
			return ErrProductionHandoff
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
			return ErrProductionHandoff
		}
	}
	return nil
}

// ValidateProductionHandoff checks that the running config is the exact
// production candidate recorded by migration. The caller separately verifies
// the ledger in the durable management store.
func ValidateProductionHandoff(dataDir string, cfg *config.Config) (ProductionHandoff, error) {
	handoff, err := ReadProductionHandoff(dataDir)
	if err != nil || cfg == nil || cfg.Storage.Profile != config.StorageProfileProduction {
		return ProductionHandoff{}, ErrProductionHandoff
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil || digestBytes(raw) != handoff.ProductionConfigDigest || digestBytes(raw) != handoff.CandidateDigest {
		return ProductionHandoff{}, ErrProductionHandoff
	}
	return handoff, nil
}
