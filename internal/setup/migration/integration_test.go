//go:build integration

package migration

import (
	"context"
	"os"
	"testing"
)

// This is deliberately opt-in and uses injected fakes. It does not claim to
// prove connectivity to a real PostgreSQL, native-raft, or Redis instance.
func TestInjectedProductionCutoverIntegration(t *testing.T) {
	if os.Getenv("CHEESEWAF_MIGRATION_INTEGRATION") != "1" {
		t.Skip("set CHEESEWAF_MIGRATION_INTEGRATION=1 to run the injected migration integration contract")
	}
	opts, _, _, _, _, _, _ := migrationFixture()
	result, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Committed || !result.TokensRotated {
		t.Fatalf("unexpected result: %+v", result)
	}
}
