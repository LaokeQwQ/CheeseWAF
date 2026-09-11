package postgres

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Keep the evidence boundary explicit: integration tests must skip without a
// real DSN, and the report must never call that skip a successful PG run.
func TestPostgresIntegrationGuardIsExplicit(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "store_integration_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if !strings.Contains(source, "CHEESEWAF_POSTGRES_TEST_DSN") || !strings.Contains(source, "t.Skip(\"CHEESEWAF_POSTGRES_TEST_DSN is not set\")") {
		t.Fatal("PostgreSQL integration tests must explicitly skip when DSN is missing")
	}
	if strings.Contains(source, "temporary PostgreSQL") && !strings.Contains(source, "t.Skip") {
		t.Fatal("integration source must not describe a temporary database as unconditional evidence")
	}
}
