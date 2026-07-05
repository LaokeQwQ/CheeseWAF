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
	if cfg.PostgreSQL.Enabled {
		sink, err := NewPostgreSQLSink(cfg.PostgreSQL)
		if err != nil {
			for _, existing := range sinks {
				_ = existing.Close()
			}
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.Elasticsearch.Enabled {
		sink, err := NewElasticsearchSink(cfg.Elasticsearch, nil)
		if err != nil {
			for _, existing := range sinks {
				_ = existing.Close()
			}
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
	var firstItems []storage.LogEntry
	var firstTotal int64
	var firstOK bool
	for _, sink := range s.sinks {
		items, total, err := sink.Query(ctx, filter)
		if err != nil {
			continue
		}
		if !firstOK {
			firstItems = items
			firstTotal = total
			firstOK = true
		}
		if total > 0 || len(items) > 0 {
			return items, total, nil
		}
	}
	if firstOK {
		return firstItems, firstTotal, nil
	}
	return nil, 0, nil
}

func (s *MultiSink) Count(ctx context.Context, filter storage.LogFilter) (int64, bool, error) {
	for _, sink := range s.sinks {
		counter, ok := sink.(interface {
			Count(context.Context, storage.LogFilter) (int64, bool, error)
		})
		if !ok {
			continue
		}
		total, supported, err := counter.Count(ctx, filter)
		if err != nil || !supported {
			continue
		}
		return total, true, nil
	}
	return 0, false, nil
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
