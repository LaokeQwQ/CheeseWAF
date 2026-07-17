package handler

import (
	"os"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
)

func TestMain(m *testing.M) {
	original := newPersistentApprovalStore
	newPersistentApprovalStore = func(string) (*ai.ApprovalStore, error) {
		return ai.NewApprovalStore(), nil
	}
	code := m.Run()
	newPersistentApprovalStore = original
	os.Exit(code)
}
