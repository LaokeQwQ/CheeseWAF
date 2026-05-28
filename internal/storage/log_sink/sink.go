package log_sink

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Sink = storage.LogSink

type MultiSink struct {
	sinks []storage.LogSink
}

func NewFromConfig(cfg config.StorageConfig, filePath string) (storage.LogSink, error) {
	file, err := NewFileSink(filePath)
	if err != nil {
		return nil, err
	}
	sinks := []storage.LogSink{file}
	if cfg.ClickHouse.Enabled {
		sink, err := NewClickHouseSink(cfg.ClickHouse, nil)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.VictoriaLogs.Enabled {
		sink, err := NewVictoriaLogsSink(cfg.VictoriaLogs, nil)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	return &MultiSink{sinks: sinks}, nil
}

func (s *MultiSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	for _, sink := range s.sinks {
		if err := sink.Write(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

func (s *MultiSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	for _, sink := range s.sinks {
		items, total, err := sink.Query(ctx, filter)
		if err == nil {
			return items, total, nil
		}
	}
	return nil, 0, nil
}

func (s *MultiSink) Flush(ctx context.Context) error {
	for _, sink := range s.sinks {
		if err := sink.Flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *MultiSink) Close() error {
	var first error
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
