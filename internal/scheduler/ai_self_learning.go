package scheduler

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
)

func AISelfLearning(runtime Runtime) TaskFunc {
	return func(ctx context.Context, task Task) error {
		cfg := runtime.AIConfig.SelfLearning
		if !cfg.Enabled {
			return nil
		}
		client := runtime.Client
		if client == nil {
			reasoning := runtime.AIConfig.ReasoningRuntimeConfig()
			if reasoning.Enabled && reasoning.APIKey != "" {
				client = ai.NewClient(reasoning, nil)
			}
		}
		report, err := ai.RunSelfLearning(ctx, ai.SelfLearningOptions{
			Config: cfg,
			Client: client,
			Sink:   runtime.Sink,
			Rules:  runtime.Store,
		})
		if err != nil {
			return err
		}
		_ = report
		return nil
	}
}
