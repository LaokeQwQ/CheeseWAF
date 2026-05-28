package log_sink

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func NewPostgreSQLSink(cfg config.PostgreSQLConfig) (Sink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.DSN == "" {
		return nil, fmt.Errorf("postgresql dsn is required")
	}
	return nil, fmt.Errorf("postgresql sink requires a database driver integration in a future build")
}
