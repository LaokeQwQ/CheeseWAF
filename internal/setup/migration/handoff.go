package migration

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode"
)

var (
	ErrHandoffProofUnavailable = errors.New("migration production handoff proof is unavailable")
	ErrHandoffProofInvalid     = errors.New("migration production handoff proof is invalid")
	ErrHandoffProofMismatch    = errors.New("migration production handoff proof does not match production target")
)

// ProductionHandoffProof is the metadata-only proof a production launcher must
// receive after temporary-to-production migration. It intentionally contains
// no credentials or database payloads. Digests bind the target configuration,
// candidate configuration, and token metadata; SnapshotID and LedgerProof bind
// the durable cut-over record; Invalidated proves that temporary capabilities
// were fenced before production was exposed.
type ProductionHandoffProof struct {
	ConfigDigest          string
	CandidateDigest       string
	ClusterID             string
	SnapshotID            string
	SnapshotProof         string
	LedgerProof           string
	TokenMetadataDigest   string
	TokenMetadataVerified bool
	Invalidated           InvalidationReceipt
}

// ProductionHandoffVerifier is implemented by the durable migration/ledger
// adapter. The composition root calls it before handing dependencies to serve.
// Implementations must not return success for an unverifiable or stale proof.
type ProductionHandoffVerifier interface {
	VerifyProductionHandoff(context.Context, ProductionHandoffProof) error
}

// ValidateProductionHandoffProof checks the non-provider portion of the
// contract. Provider-specific ledger checks remain behind
// ProductionHandoffVerifier so this package never reaches into PostgreSQL or
// another durable backend.
func ValidateProductionHandoffProof(proof ProductionHandoffProof, expectedClusterID string) error {
	if err := strictHandoffIdentity(expectedClusterID); err != nil {
		return fmt.Errorf("%w: cluster target: %v", ErrHandoffProofInvalid, err)
	}
	if proof.ClusterID != expectedClusterID {
		return fmt.Errorf("%w: cluster ID", ErrHandoffProofMismatch)
	}
	for name, value := range map[string]string{
		"config digest":         proof.ConfigDigest,
		"candidate digest":      proof.CandidateDigest,
		"token metadata digest": proof.TokenMetadataDigest,
	} {
		if err := validHandoffDigest(value); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrHandoffProofInvalid, name, err)
		}
	}
	for name, value := range map[string]string{
		"cluster ID":     proof.ClusterID,
		"snapshot ID":    proof.SnapshotID,
		"snapshot proof": proof.SnapshotProof,
		"ledger proof":   proof.LedgerProof,
	} {
		if err := strictHandoffIdentity(value); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrHandoffProofInvalid, name, err)
		}
	}
	if !proof.TokenMetadataVerified {
		return fmt.Errorf("%w: token metadata is not verified", ErrHandoffProofInvalid)
	}
	if !proof.Invalidated.Complete() {
		return fmt.Errorf("%w: temporary invalidation is incomplete", ErrHandoffProofInvalid)
	}
	return nil
}

func validHandoffDigest(value string) error {
	if len(value) != 64 {
		return errors.New("digest must be a 64-character hexadecimal value")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("digest must be hexadecimal")
	}
	return nil
}

func strictHandoffIdentity(value string) error {
	if value == "" {
		return errors.New("value is required")
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("value must not contain whitespace or invisible characters")
		}
	}
	return nil
}
