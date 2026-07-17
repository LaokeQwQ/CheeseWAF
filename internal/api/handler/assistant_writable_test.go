package handler

import (
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestEnsureAssistantConfigWritableRespectsLocalFreeze(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	h := &Handler{Config: &cfg}
	h.configWriteFrozen = true
	h.configFreezeReason = "runtime rollback failed"

	err := ensureAssistantConfigWritable(h)
	if err == nil {
		t.Fatal("expected freeze to block assistant config writes")
	}
	if !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelfLearningRuleWriteAllowedRespectsLocalFreeze(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	h := &Handler{Config: &cfg}
	h.configWriteFrozen = true
	h.configFreezeReason = "persist failed"

	err := h.selfLearningRuleWriteAllowed(nil)
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("expected freeze error, got %v", err)
	}
}
