package cli

import (
	"context"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestPolicyEpochSourceRejectsUnestablishedEpoch(t *testing.T) {
	if _, err := (policyEpochSource{read: func() uint64 { return 0 }}).CurrentEpoch(context.Background(), "tenant-a"); err == nil {
		t.Fatal("zero policy epoch must be rejected")
	}
	epoch, err := (policyEpochSource{read: func() uint64 { return 42 }}).CurrentEpoch(context.Background(), "tenant-a")
	if err != nil || epoch != 42 {
		t.Fatalf("epoch=%d err=%v", epoch, err)
	}
	if _, err := (policyEpochSource{}).CurrentEpoch(context.Background(), "tenant-a"); err == nil {
		t.Fatal("missing epoch reader must be rejected")
	}
}

func TestOpenDurableTokenServiceRejectsMissingDSN(t *testing.T) {
	if _, _, err := openDurableTokenService(context.Background(), config.ManagementAPITokenDurableConfig{}, func() uint64 { return 1 }); err == nil {
		t.Fatal("empty DSN must fail closed")
	}
	if _, _, err := openDurableTokenService(context.Background(), config.ManagementAPITokenDurableConfig{DSNEnv: "CHEESEWAF_TEST_UNSET_TOKEN_DSN"}, func() uint64 { return 1 }); err == nil {
		t.Fatal("unset DSN environment variable must fail closed")
	}
}
