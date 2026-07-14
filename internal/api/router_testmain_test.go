package api

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
)

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "cheesewaf-api-test-")
	if err != nil {
		panic(err)
	}
	original := newAuditor
	originalApprovals := newRouterAssistantApprovalStore
	var sequence atomic.Uint64
	newAuditor = func(string) *middleware.Auditor {
		name := fmt.Sprintf("audit-%d.log", sequence.Add(1))
		return middleware.NewAuditor(filepath.Join(root, name))
	}
	newRouterAssistantApprovalStore = ai.NewApprovalStore
	code := m.Run()
	newAuditor = original
	newRouterAssistantApprovalStore = originalApprovals
	_ = os.RemoveAll(root)
	os.Exit(code)
}
