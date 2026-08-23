package log_sink

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Sink = storage.LogSink

type MultiSink struct {
	sinks []storage.LogSink
}

func NewFromConfig(cfg config.StorageConfig, filePath string) (storage.LogSink, error) {
	return NewFromConfigWithFile(cfg, config.FileLogConfig{Path: filePath})
}

func NewFromConfigWithFile(cfg config.StorageConfig, fileConfig config.FileLogConfig) (storage.LogSink, error) {
	var maxSizeBytes int64
	var err error
	if fileConfig.MaxSize != "" {
		maxSizeBytes, err = config.ParseFileLogSize(fileConfig.MaxSize)
		if err != nil {
			return nil, fmt.Errorf("parse file log max size: %w", err)
		}
	}
	file, err := NewFileSinkWithRotation(fileConfig.Path, maxSizeBytes, fileConfig.MaxBackups)
	if err != nil {
		return nil, err
	}
	sinks := []storage.LogSink{file}
	if cfg.ClickHouse.Enabled {
		sink, err := NewClickHouseSink(cfg.ClickHouse, nil)
		if err != nil {
			_ = closeLogSinks(sinks)
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.VictoriaLogs.Enabled {
		sink, err := NewVictoriaLogsSink(cfg.VictoriaLogs, nil)
		if err != nil {
			_ = closeLogSinks(sinks)
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.PostgreSQL.Enabled {
		sink, err := NewPostgreSQLSink(cfg.PostgreSQL)
		if err != nil {
			_ = closeLogSinks(sinks)
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	if cfg.Elasticsearch.Enabled {
		sink, err := NewElasticsearchSink(cfg.Elasticsearch, nil)
		if err != nil {
			_ = closeLogSinks(sinks)
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	return &MultiSink{sinks: sinks}, nil
}

func (s *MultiSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Write(ctx, entry); err != nil {
			errs = append(errs, fmt.Errorf("write %T: %w", sink, err))
		}
	}
	return errors.Join(errs...)
}

func (s *MultiSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	ordered := remoteFirstLogSinks(s.sinks)
	var firstItems []storage.LogEntry
	var firstTotal int64
	var firstOK bool
	for _, sink := range ordered {
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
	for _, sink := range remoteFirstLogSinks(s.sinks) {
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

func remoteFirstLogSinks(sinks []storage.LogSink) []storage.LogSink {
	ordered := make([]storage.LogSink, 0, len(sinks))
	local := make([]storage.LogSink, 0, 1)
	for _, sink := range sinks {
		if _, ok := sink.(*FileSink); ok {
			local = append(local, sink)
			continue
		}
		ordered = append(ordered, sink)
	}
	return append(ordered, local...)
}

func (s *MultiSink) Flush(ctx context.Context) error {
	return runAllLogSinks(s.sinks, func(sink storage.LogSink) error {
		if err := sink.Flush(ctx); err != nil {
			return fmt.Errorf("flush %T: %w", sink, err)
		}
		return nil
	})
}

func (s *MultiSink) Close() error {
	return closeLogSinks(s.sinks)
}

func closeLogSinks(sinks []storage.LogSink) error {
	return runAllLogSinks(sinks, func(sink storage.LogSink) error {
		if err := sink.Close(); err != nil {
			return fmt.Errorf("close %T: %w", sink, err)
		}
		return nil
	})
}

func runAllLogSinks(sinks []storage.LogSink, operation func(storage.LogSink) error) error {
	if len(sinks) == 0 {
		return nil
	}
	errs := make([]error, len(sinks))
	var wait sync.WaitGroup
	wait.Add(len(sinks))
	for index, sink := range sinks {
		index, sink := index, sink
		go func() {
			defer wait.Done()
			if sink == nil {
				return
			}
			errs[index] = operation(sink)
		}()
	}
	wait.Wait()
	return errors.Join(errs...)
}
