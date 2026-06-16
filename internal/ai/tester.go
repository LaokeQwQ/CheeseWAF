package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestConnection(ctx context.Context, cfg config.AIConfig) error {
	if !cfg.Enabled {
		return fmt.Errorf("ai is disabled")
	}
	client := NewClientWithTimeout(cfg, 45*time.Second)
	reply, err := client.Complete(ctx, []Message{
		{Role: "system", Content: "Reply with OK only."},
		{Role: "user", Content: "Connectivity check."},
	})
	if err != nil {
		return err
	}
	if reply == "" {
		return fmt.Errorf("ai api returned an empty response")
	}
	return nil
}
