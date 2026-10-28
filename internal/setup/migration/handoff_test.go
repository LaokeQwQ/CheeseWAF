package migration

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func validProductionHandoffProof() ProductionHandoffProof {
	return ProductionHandoffProof{
		ConfigDigest:          strings.Repeat("a", 64),
		CandidateDigest:       strings.Repeat("b", 64),
		ClusterID:             "cluster-a",
		SnapshotID:            "snapshot-a",
		SnapshotProof:         "snapshot-proof-a",
		LedgerProof:           "ledger-proof-a",
		TokenMetadataDigest:   strings.Repeat("c", 64),
		TokenMetadataVerified: true,
		Invalidated:           InvalidationReceipt{Sessions: true, Setup: true, Join: true, CAPTCHA: true, Locks: true},
	}
}

func TestValidateProductionHandoffProof(t *testing.T) {
	proof := validProductionHandoffProof()
	if err := ValidateProductionHandoffProof(proof, "cluster-a"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProductionHandoffProof){
		"config digest":           func(p *ProductionHandoffProof) { p.ConfigDigest = "short" },
		"candidate digest":        func(p *ProductionHandoffProof) { p.CandidateDigest = strings.Repeat("z", 64) },
		"cluster mismatch":        func(p *ProductionHandoffProof) { p.ClusterID = "cluster-b" },
		"missing ledger proof":    func(p *ProductionHandoffProof) { p.LedgerProof = "" },
		"unverified tokens":       func(p *ProductionHandoffProof) { p.TokenMetadataVerified = false },
		"incomplete invalidation": func(p *ProductionHandoffProof) { p.Invalidated.Locks = false },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := proof
			mutate(&mutated)
			if err := ValidateProductionHandoffProof(mutated, "cluster-a"); !errors.Is(err, ErrHandoffProofInvalid) && !errors.Is(err, ErrHandoffProofMismatch) {
				t.Fatalf("error=%v, want invalid or mismatch proof", err)
			}
		})
	}
}

func TestProductionHandoffVerifierContractIsContextAware(t *testing.T) {
	var _ ProductionHandoffVerifier = handoffVerifierFunc(func(context.Context, ProductionHandoffProof) error { return nil })
}

type handoffVerifierFunc func(context.Context, ProductionHandoffProof) error

func (f handoffVerifierFunc) VerifyProductionHandoff(ctx context.Context, proof ProductionHandoffProof) error {
	return f(ctx, proof)
}
