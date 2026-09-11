package cli

import (
	"context"
	"errors"
	"testing"
)

func TestDefaultProductionDependencyFactoryKeepsApprovalFailClosed(t *testing.T) {
	factory := NewProductionDependencyFactory()
	_, err := factory.OpenApproval(context.Background(), ProductionStartupOptions{})
	if !errors.Is(err, ErrProductionApprovalUnavailable) {
		t.Fatalf("default approval opener error = %v, want ErrProductionApprovalUnavailable", err)
	}
}
