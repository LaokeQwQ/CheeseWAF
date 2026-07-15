package cli

import (
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

func timekeeperConfigFromConfig(cfg config.TimeSyncConfig) timekeeper.Config {
	return timekeeper.Config{
		Enabled:              cfg.Enabled,
		Sources:              append([]string(nil), cfg.Sources...),
		ReselectInterval:     cfg.SelectionInterval,
		SyncInterval:         cfg.SyncInterval,
		QueryTimeout:         cfg.Timeout,
		MaxAcceptedOffset:    cfg.MaxAcceptedOffset,
		MaxRootDispersion:    cfg.MaxRootDispersion,
		SamplesPerSource:     cfg.SamplesPerSource,
		ConsistencyThreshold: cfg.ConsensusTolerance,
	}
}
